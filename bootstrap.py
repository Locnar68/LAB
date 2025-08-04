#!/usr/bin/env python3
"""
Automic AWS Bootstrap Script (Python Version)
Fully automated end-to-end provisioning and installation:
  - AWS: VPC, SG, key pair, EC2 (DB, AE, AWI)
  - PostgreSQL setup, contrib, auth, and tuning
  - Automic AEDB, AE Engine, AWI installs via SSH
  - Utilities (ucybdbld) loading
  - CAPKI & TLS configuration
  - Tablespace & schema creation
  - AE Engine process startup
  - Web Interface startup
  - Final verification across hosts
"""

import os
import sys
import argparse
import logging
import base64
from pathlib import Path

import boto3
import botocore
import paramiko

# Silence Paramiko logs
import logging as _logging
_logging.getLogger('paramiko').setLevel(_logging.WARNING)
_logging.getLogger('paramiko.transport').setLevel(_logging.WARNING)

# Helpers

def banner(text):
    line = '=' * max(30, len(text) + 10)
    logging.info(f"\n{line}\n   {text}\n{line}\n")

def get_default(env_var, default):
    return os.environ.get(env_var, default)

def ensure_directory(path):
    p = Path(path).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p

def write_pem(path: Path, pem_text: str):
    path.write_text(pem_text)
    path.chmod(0o600)

# AWS primitives

def ensure_vpc(ec2, vpc_id):
    if vpc_id:
        return vpc_id
    vpcs = ec2.describe_vpcs(Filters=[{'Name':'is-default','Values':['true']}])['Vpcs']
    if not vpcs:
        raise RuntimeError('No default VPC; specify --vpc-id')
    return vpcs[0]['VpcId']

def ensure_security_group(ec2, vpc_id, name):
    retries = 0
    if not vpc_id:
        raise RuntimeError('VPC ID must be provided')
    # Check for existing SG
    resp = ec2.describe_security_groups(
        Filters=[{'Name':'vpc-id','Values':[vpc_id]}, {'Name':'group-name','Values':[name]}]
    )
    if resp['SecurityGroups']:
        sg = resp['SecurityGroups'][0]
        logging.info(f"SG exists: {name} ({sg['GroupId']})")
        return sg['GroupId']
    # Create new SG
    sg = ec2.create_security_group(Description='Automic SG', GroupName=name, VpcId=vpc_id)
    sg_id = sg['GroupId']
    # Ingress rules with exponential backoff
    for proto, port in [('tcp',22),('tcp',5432),('tcp',2217),('tcp',2218),('tcp',2219),('tcp',8080)]:
        retries = 0
        while True:
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': proto,
                        'FromPort': port,
                        'ToPort': port,
                        'IpRanges':[{'CidrIp':'0.0.0.0/0'}]
                    }]
                )
                break
            except botocore.exceptions.ClientError as e:
                err_code = e.response.get('Error', {}).get('Code', '')
                msg = str(e)
                if 'InvalidPermission.Duplicate' in msg:
                    break
                # Handle throttling
                if err_code in ('RequestLimitExceeded',) or 'Throttling' in msg:
                    if retries < 5:
                        wait = 2 ** retries
                        logging.warning(f"Throttled on SG rule {port}, retrying in {wait}s")
                        time.sleep(wait)
                        retries += 1
                        continue
                raise
    return sg_id

def ensure_key_pair(ec2, name, key_dir):
    key_path = ensure_directory(key_dir) / f"{name}.pem"
    try:
        ec2.describe_key_pairs(KeyNames=[name])
        if key_path.exists():
            return key_path
        raise RuntimeError('Key exists but PEM missing')
    except botocore.exceptions.ClientError:
        kp = ec2.create_key_pair(KeyName=name)
        write_pem(key_path, kp['KeyMaterial'])
        return key_path

def find_instance(ec2, name):
    res = ec2.describe_instances(
        Filters=[{'Name':'tag:Name','Values':[name]}, {'Name':'instance-state-name','Values':['pending','running','stopped']}]
    )
    insts = sum((r['Instances'] for r in res['Reservations']), [])
    return sorted([i for i in insts if any(t['Value']==name for t in i.get('Tags', []))], key=lambda x: x['LaunchTime'], reverse=True)

def ensure_instance(ec2, name, itype, key_name, sg_id, ami, user_data):
    found = find_instance(ec2, name)
    if found:
        logging.info(f"Instance exists: {name}")
        return found[0]['InstanceId']
    r = ec2.run_instances(
        ImageId=ami,
        InstanceType=itype,
        MinCount=1,
        MaxCount=1,
        KeyName=key_name,
        SecurityGroupIds=[sg_id],
        UserData=base64.b64encode(user_data.encode()).decode(),
        TagSpecifications=[{'ResourceType':'instance','Tags':[{'Key':'Name','Value':name}]}]
    )
    return r['Instances'][0]['InstanceId']

def wait_instances(ec2, ids):
    # Wait for instances to enter running state, with timeout and retries
    waiter1 = ec2.get_waiter('instance_running')
    try:
        waiter1.wait(InstanceIds=ids, WaiterConfig={'Delay': 15, 'MaxAttempts': 40})  # ~10 minutes max
    except botocore.exceptions.WaiterError as e:
        logging.error(f"Timeout waiting for instances to run: {e}")
        raise
    # Then wait for status checks to pass
    waiter2 = ec2.get_waiter('instance_status_ok')
    try:
        waiter2.wait(InstanceIds=ids, WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
    except botocore.exceptions.WaiterError as e:
        logging.error(f"Timeout waiting for instance status ok: {e}")
        raise

def get_ip(ec2,iid):
    return ec2.describe_instances(InstanceIds=[iid])['Reservations'][0]['Instances'][0]['PublicIpAddress']

# Main

def main():
    parser = argparse.ArgumentParser(description='Automic AWS Bootstrap')
    parser.add_argument('--region', default=get_default('AWS_REGION','us-east-1'))
    parser.add_argument('--vpc-id', default=os.environ.get('AUTOMIC_VPCID',''))
    parser.add_argument('--sg-name', default=get_default('AUTOMIC_SGNAME','automic-sg'))
    parser.add_argument('--key-name', default=get_default('AUTOMIC_KEYNAME','automic_key'))
    parser.add_argument('--key-dir', default=get_default('USERPROFILE','~/.ssh'))
    parser.add_argument('--db-name', default=get_default('AUTOMIC_DBNAME','automic-postgres16'))
    parser.add_argument('--ae-name', default=get_default('AUTOMIC_AENAME','automic-ae'))
    parser.add_argument('--awi-name', default=get_default('AUTOMIC_AWINAME','automic-awi'))
    parser.add_argument('--db-type', default=get_default('AUTOMIC_DB_TYPE','t2.micro'))
    parser.add_argument('--ae-type', default=get_default('AUTOMIC_AE_TYPE','t2.micro'))
    parser.add_argument('--awi-type', default=get_default('AUTOMIC_AWI_TYPE','t2.micro'))
    parser.add_argument('--db-sys-pass', default=get_default('AUTOMIC_DB_SYS_PASS','postgres'))
    args = parser.parse_args()

    from logging.handlers import RotatingFileHandler

    # Define log file path
    log_file = Path('bootstrap.log')
    # Logging setup with rotation and timestamps
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # Rotating file handler
    fh = RotatingFileHandler(str(log_file), maxBytes=10*1024*1024, backupCount=3)
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(fh)
    # Console handler with timestamps
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(ch)
    logger.info(f"Logging to {log_file}")

    # Environment diagnostics
    banner('Environment diagnostics')
    session = boto3.Session(region_name=args.region)
    ec2 = session.client('ec2')
    sts = session.client('sts')
    account = sts.get_caller_identity()['Account']
    logging.info(f"AWS Account: {account} | Region: {args.region}")

    # Network setup
    banner('VPC resolution')
    vpc_id = ensure_vpc(ec2, args.vpc_id)
    banner('Security group')
    sg_id = ensure_security_group(ec2, vpc_id, args.sg_name)
    banner('Key pair')
    key_path = ensure_key_pair(ec2, args.key_name, args.key_dir)

    # AMI lookup
    ssm = session.client('ssm')
    ami = ssm.get_parameter(Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64')['Parameter']['Value']
    logging.info(f"AMI: {ami}")

    # User-data scripts
    db_ud = f"""#!/bin/bash -xe
sudo dnf update -y
sudo dnf install -y postgresql16-server postgresql16 postgresql16-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
sudo -u postgres psql -c \"ALTER USER postgres WITH PASSWORD '{args.db_sys_pass}';\"
sudo passwd postgres <<EOF
{args.db_sys_pass}
{args.db_sys_pass}
EOF
echo "postgres ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/postgres
PGDATA=/var/lib/pgsql/16/data
sudo bash -c \"echo 'host all all 0.0.0.0/0 md5' >> $PGDATA/pg_hba.conf\"
sudo bash -c \"cat <<EOL >> $PGDATA/postgresql.conf
listen_addresses='*'
statement_timeout='300s'
idle_in_transaction_session_timeout='300s'
EOL\"
sudo systemctl restart postgresql-16
"""
    ae_ud = """#!/bin/bash
yum install -y java-17-amazon-corretto
"""
    awi_ud = ae_ud

    # Launch instances
    banner('Launching instances')
    db_id = ensure_instance(ec2, args.db_name, args.db_type, args.key_name, sg_id, ami, db_ud)
    ae_id = ensure_instance(ec2, args.ae_name, args.ae_type, args.key_name, sg_id, ami, ae_ud)
    awi_id = ensure_instance(ec2, args.awi_name, args.awi_type, args.key_name, sg_id, ami, awi_ud)
    banner('Waiting for instances')
    wait_instances(ec2, [db_id, ae_id, awi_id])

    # Retrieve IPs
    db_ip = get_ip(ec2, db_id)
    ae_ip = get_ip(ec2, ae_id)
    awi_ip = get_ip(ec2, awi_id)

        # Automic AEDB install
    banner('Installing Automic AEDB')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=db_ip, username='ec2-user', key_filename=str(key_path))
    sftp = ssh.open_sftp()
    local_zip = Path(__file__).parent / 'Automic.Automation_24.4.1_2025-07-25.zip'
    remote_zip = '/home/ec2-user/Automic.zip'
    logging.info(f"Transferring {local_zip} to {remote_zip}")
    sftp.put(str(local_zip), remote_zip)
    response = f"""jdbc.url=jdbc:postgresql://{db_ip}:5432/{args.db_name}
jdbc.user=aauser
jdbc.password={args.db_sys_pass}
"""
    with sftp.open('/home/ec2-user/db_response.properties', 'w') as f:
        f.write(response)
    sftp.close()
    # Prepare install directory and prerequisites
    cmds = [
        'sudo mkdir -p /opt/automic/install && sudo chown ec2-user:ec2-user /opt/automic/install',
        'sudo dnf install -y unzip java-17-amazon-corretto',
        'sudo unzip -o /home/ec2-user/Automic.zip -d /opt/automic/install',
        'sudo chmod +x /opt/automic/install/install.sh',
        'sudo bash -c "cd /opt/automic/install && ./install.sh -silent -responseFile /home/ec2-user/db_response.properties > install.log 2>&1"'
    ]
    for c in cmds:
        logging.info(f"Running: {c}")
        stdin, stdout, stderr = ssh.exec_command(c)
        exit_code = stdout.channel.recv_exit_status()
        # After unzip, optional debug removed
        if exit_code != 0:
            err = stderr.read().decode()
            logging.error(f"Installer failed ({c}): {err}")
            raise RuntimeError(f"AEDB install failed at: {c}")
    logging.info('Automic AEDB installation complete')
    ssh.close()

    # Tablespaces & schema
    banner('Configuring tablespaces & schema')
    db2 = paramiko.SSHClient(); db2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    db2.connect(hostname=db_ip, username='ec2-user', key_filename=str(key_path))
    ts_cmds = [
        'sudo mkdir -p /opt/db/tablespaces/ae_data /opt/db/tablespaces/ae_index',
        'chown -R postgres:postgres /opt/db/tablespaces',
        f"psql -U postgres -c \"CREATE USER aauser WITH PASSWORD '{args.db_sys_pass}';\"",
        "psql -U postgres -c \"CREATE TABLESPACE ae_data OWNER aauser LOCATION '/opt/db/tablespaces/ae_data';\"",
        "psql -U postgres -c \"CREATE TABLESPACE ae_index OWNER aauser LOCATION '/opt/db/tablespaces/ae_index';\"",
        f"psql -U postgres -c \"CREATE DATABASE aadb OWNER aauser TABLESPACE ae_data ENCODING 'UTF8';\"",
        'psql -U postgres -d aadb -c "CREATE SCHEMA aaschema AUTHORIZATION aauser;"',
        'psql -U postgres -d aadb -c "ALTER ROLE aauser SET search_path TO aaschema;"'
    ]
    for c in ts_cmds:
        logging.info(f"Running: {c}")
        stdin,stdout,stderr = db2.exec_command(c)
        if stdout.channel.recv_exit_status(): raise RuntimeError(stderr.read().decode())
    db2.close()

    # Utilities (ucybdbld)
    banner('Installing Utilities')
    util = paramiko.SSHClient(); util.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    util.connect(hostname=db_ip, username='ec2-user', key_filename=str(key_path))
    util_sftp = util.open_sftp()
    util_sftp.put(str(Path(__file__).parent / 'utillx6.tar.gz'), '/home/ec2-user/utillx6.tar.gz')
    util_sftp.close()
    util_cmds = [
        'sudo mkdir -p /opt/automic/Utility && sudo chown ec2-user:ec2-user /opt/automic/Utility',
        'tar -xzvf /home/ec2-user/utillx6.tar.gz -C /opt/automic/Utility',
        # Identify utility directory
        'UTIL_DIR=$(find /opt/automic/Utility -maxdepth 1 -mindepth 1 -type d | head -n1)',
        # Configure ucybdbld.ini connection string
        f"sudo sed -i 's|^url=.*|url=jdbc:postgresql://{db_ip}:5432/aadb|' $UTIL_DIR/bin/ucybdbld.ini",
        f"sudo sed -i 's|^user=.*|user=aauser|' $UTIL_DIR/bin/ucybdbld.ini",
        f"sudo sed -i 's|^password=.*|password={args.db_sys_pass}|' $UTIL_DIR/bin/ucybdbld.ini",
        # Load utilities into AEDB
        'cd $UTIL_DIR && sudo bash ./ucybdbld -B -X $UTIL_DIR/db/general -E $UTIL_DIR/db/initialdata'
    ]
    for c in util_cmds:
        logging.info(f"Running: {c}")
        stdin,stdout,stderr = util.exec_command(c)
        if stdout.channel.recv_exit_status(): raise RuntimeError(stderr.read().decode())
    util.close()

    # CAPKI & TLS
    banner('CAPKI & TLS setup')
    cap = paramiko.SSHClient(); cap.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cap.connect(hostname=ae_ip, username='ec2-user', key_filename=str(key_path))
    cap_cmds = [
        'mkdir -p /opt/CA/SharedComponents/CAPKI',
        'cd /opt/automic/install/Tools/CA.PKI/unix/linux/x64 && sudo chmod +x setup && sudo ./setup install caller=automic env=all',
        'echo "export CAPKIHOME=/opt/CA/SharedComponents/CAPKI" | sudo tee /etc/profile.d/capki.sh'
    ]
    for c in cap_cmds:
        logging.info(f"Running: {c}")
        stdin,stdout,stderr = cap.exec_command(c)
        if stdout.channel.recv_exit_status(): raise RuntimeError(stderr.read().decode())
    keystore = Path(__file__).parent / 'ae_keystore'
    if keystore.exists():
        sftp2 = cap.open_sftp()
        cap.exec_command('mkdir -p /opt/automic/tls && chown ec2-user:ec2-user /opt/automic/tls')
        sftp2.put(str(keystore), f"/opt/automic/tls/{keystore.name}")
        sftp2.close()
    cap.close()

    # AE Engine config
    banner('Configuring AE Engine')
    cfg = paramiko.SSHClient(); cfg.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cfg.connect(hostname=ae_ip, username='ec2-user', key_filename=str(key_path))
    # Install platform-specific PostgreSQL client libraries for AE Engine dependencies
    logging.info('Installing PostgreSQL client libraries on AE host')
    cfg.exec_command('sudo dnf install -y postgresql-libs')
    stdin,stdout,_ = cfg.exec_command("find /opt/automic/AutomationEngine -maxdepth 1 -mindepth 1 -type d | head -n1")
    ae_dir = stdout.read().decode().strip()
    sftp = cfg.open_sftp()
    sftp.put(str(Path(__file__).parent / 'postgresql-42.7.5.jar'), f"{ae_dir}/bin/lib/postgresql-42.7.5.jar")
    sftp.close()
    cfg_cmds = [
        # Set JDBC connection
        f"sudo sed -i 's|^jdbc.url=.*|jdbc.url=jdbc:postgresql://{db_ip}:5432/{args.db_name}|' {ae_dir}/config/ucsvr.ini",
        # Set JDBC driver class
        "sudo sed -i 's|^jdbc.driver.class=.*|jdbc.driver.class=org.postgresql.Driver|' {ae_dir}/config/ucsvr.ini",
        # Configure server host and system name
        f"sudo sed -i 's|^server.host=.*|server.host={ae_ip}|' {ae_dir}/config/ucsvr.ini",
        f"sudo sed -i 's|^server.system=.*|server.system={args.ae_name}|' {ae_dir}/config/ucsvr.ini"
    ]
    for c in cfg_cmds:
        logging.info(f"Running: {c}")
        stdin,stdout,stderr = cfg.exec_command(c)
        if stdout.channel.recv_exit_status(): raise RuntimeError(stderr.read().decode())
    cfg.close()

    # Start AE processes
    banner('Starting AE processes')
    proc = paramiko.SSHClient(); proc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    proc.connect(hostname=ae_ip, username='ec2-user', key_filename=str(key_path))
    for c in [
        f"cd {ae_dir}/bin && nohup ./ucsrvwp > ae_wp.log 2>&1 &",
        f"cd {ae_dir}/bin && nohup ./ucsrvcp > ae_cp.log 2>&1 &",
        f"cd {ae_dir}/bin && nohup java -jar ucsrvjp.jar > ae_jp.log 2>&1 &",
        f"cd {ae_dir}/bin && nohup java -jar ucsrvjr.jar --rest > ae_rest.log 2>&1 &"
    ]:
        logging.info(f"Running: {c}")
        proc.exec_command(c)
    proc.close()

    # AWI install & start
    banner('Installing AWI')
    awi = paramiko.SSHClient(); awi.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    awi.connect(hostname=awi_ip, username='ec2-user', key_filename=str(key_path))
    # replicate AEDB steps for AWI
    sftp_awi = awi.open_sftp()
    sftp_awi.put(str(local_zip), remote_zip)
    sftp_awi.open('/home/ec2-user/awi_response.properties','w').write(response.replace('aauser','aauser'))
    sftp_awi.close()
    awi.exec_command('sudo dnf install -y java-17-amazon-corretto && echo "export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))" | sudo tee /etc/profile.d/java.sh')
    cmds_awi = [
        'sudo mkdir -p /opt/automic/WebInterface && sudo chown ec2-user:ec2-user /opt/automic/WebInterface',
        'unzip /home/ec2-user/Automic.zip -d /opt/automic/WebInterface',
        'INSTALL_DIR3=$(dirname $(find /opt/automic/WebInterface -type f -name install.sh | head -n1))',
        'cd $INSTALL_DIR3 && sudo bash install.sh -silent -responseFile /home/ec2-user/awi_response.properties',
        f"cd $INSTALL_DIR3 && nohup java -jar aa-webui-launcher.jar > awi.log 2>&1 &"
    ]
    for c in cmds_awi:
        logging.info(f"Running: {c}")
        stdin,stdout,stderr = awi.exec_command(c)
        if stdout.channel.recv_exit_status(): raise RuntimeError(stderr.read().decode())
    awi.close()

    # Automic Service Manager installation
    banner('Installing Service Manager')
    sm = paramiko.SSHClient(); sm.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sm.connect(hostname=ae_ip, username='ec2-user', key_filename=str(key_path))
    # Transfer Service Manager ZIP
    sftp_sm = sm.open_sftp()
    sftp_sm.put(str(Path(__file__).parent / 'ucsmgrlx6.tar.gz'), '/home/ec2-user/ucsmgrlx6.tar.gz')
    sftp_sm.close()
    sm_cmds = [
        'sudo mkdir -p /opt/automic/ServiceManager && sudo chown ec2-user:ec2-user /opt/automic/ServiceManager',
        'sudo tar -xzvf /home/ec2-user/ucsmgrlx6.tar.gz -C /opt/automic/ServiceManager',
        'SM_DIR=$(find /opt/automic/ServiceManager -maxdepth 1 -mindepth 1 -type d | head -n1)',
        f'sudo sed -i "s|^connect.server=.*|connect.server={ae_ip};rpc/uc4|" $SM_DIR/config/ucybsmgr.ini',
        'sudo sed -i "s/-d64//g" $SM_DIR/config/uc4.smd',
        'cd $SM_DIR/bin && nohup ./ucybsmgr -i db -customer Automic > sm.log 2>&1 &'
    ]
    for c in sm_cmds:
        logging.info(f"Running: {c}")
        stdin,stdout,stderr = sm.exec_command(c)
        if stdout.channel.recv_exit_status(): raise RuntimeError(stderr.read().decode())
    sm.close()
    awi.exec_command('sudo dnf install -y java-11-openjdk && echo "export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))" | sudo tee /etc/profile.d/java.sh')
    cmds_awi = [
        'sudo mkdir -p /opt/automic/WebInterface && sudo chown ec2-user:ec2-user /opt/automic/WebInterface',
        'unzip /home/ec2-user/Automic.zip -d /opt/automic/WebInterface',
        'INSTALL_DIR3=$(dirname $(find /opt/automic/WebInterface -type f -name install.sh | head -n1))',
        'cd $INSTALL_DIR3 && sudo bash install.sh -silent -responseFile /home/ec2-user/awi_response.properties',
        f"cd $INSTALL_DIR3 && nohup java -jar aa-webui-launcher.jar > awi.log 2>&1 &"
    ]
    for c in cmds_awi:
        logging.info(f"Running: {c}")
        stdin,stdout,stderr = awi.exec_command(c)
        if stdout.channel.recv_exit_status(): raise RuntimeError(stderr.read().decode())
    awi.close()

    # Verification
    banner('Verifying all hosts')
    verifier = paramiko.SSHClient(); verifier.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for role, host, checks in [
        ('DB', db_ip, [
            'test -d /opt/db/tablespaces/ae_data && echo "ae_data OK"',
            'test -d /opt/db/tablespaces/ae_index && echo "ae_index OK"',
            'psql -U aauser -d aadb -c "select 1;"'
        ]),
        ('AE', ae_ip, [
            'pgrep -f ucsrvwp && echo "WP OK"',
            'pgrep -f ucsrvcp && echo "CP OK"'
        ]),
        ('AWI', awi_ip, [
            'pgrep -f aa-webui-launcher.jar && echo "AWI OK"'
        ])
    ]:
        verifier.connect(hostname=host, username='ec2-user', key_filename=str(key_path))
        for c in checks:
            stdin,stdout,stderr = verifier.exec_command(c)
            out = stdout.read().decode().strip()
            if out:
                logging.info(f"{role} check: {out}")
            else:
                logging.warning(f"{role} check failed: {c}")
        verifier.close()

if __name__ == '__main__':
    main()
