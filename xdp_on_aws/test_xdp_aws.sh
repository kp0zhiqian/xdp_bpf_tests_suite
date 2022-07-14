#!/bin/bash
# This is a script used to run xdp sample programs testing on AWS platform.
# Before this script please make sure you have below object defined on your AWS
# [ ] a subnet used for XDP test traffic
# [ ] a subnet used for XDP mgmt traffic
# [ ] a test security group that allow ICMP/SSH/UDP port 9
# [ ] a mgmt security group that only allow ssh inbound
# [ ] a key pair with name xdp_test
# [ ] key pair pem file in your local env



# ---------------------------Global Params-------------------------------

KEY_PAIR_NAME=""
KEY_FILE_PATH=""

MGMT_SG_GROUP="sg-xxxxxxxxxxxxxx"
TEST_SG_GROUP="sg-xxxxxxxxxxxxxx"

MGMT_SUBNET_ID="subnet-xxxxxxxxxxxxx" # 172.31.80.0/20
TEST_SUBNET_ID="subnet-xxxxxxxxxxxxx" # 172.31.64.0/20
IP_ADD_PKTGEN_1="" # E.g. 172.31.74.1
IP_ADD_DUT_1="" # E.g. 172.31.74.2
IP_ADD_PKTGEN_2="" # E.g. 172.31.74.3
IP_ADD_DUT_2="" # E.g. 172.31.74.4

INSTANCE_TYPE="" # E.g. t3.xlarge, make sure the instance type has more than 1 cpu and 4G mem
DEFAULT_AMI_ID="ami-xxxxxxxxxxxxx"
# --------------------------------------------------------------------------

# ------------------Shared Library Start--------------------

log() {
    local log_time=$(date +%s)
    local time_diff=$((log_time-START_TIME))
    local min=$((time_diff / 60))
    local sec=$((time_diff % 60))
    echo "[${min}:${sec}]: $*" >&2
}

err() {
    log $*
    log "Exit script."
    exit 1
}

clean_resource() {
    # log "Deleting the temp rpm files at local"
    # rm -f kernel-selftests-internal-${uname_r}.rpm
    # rm -f kernel-modules-internal-${uname_r}.rpm

    log "Cleaning AWS resources"
    # Detach network interfaces from instances
    aws ec2 detach-network-interface --attachment-id ${network_attachment_id_dut_1} --no-force
    aws ec2 detach-network-interface --attachment-id ${network_attachment_id_dut_2} --no-force
    aws ec2 detach-network-interface --attachment-id ${network_attachment_id_pktgen_1} --no-force 
    aws ec2 detach-network-interface --attachment-id ${network_attachment_id_pktgen_2} --no-force
    sleep 5
    # Delete network interfaces
    aws ec2 delete-network-interface --network-interface-id ${network_interface_id_dut_1}
    aws ec2 delete-network-interface --network-interface-id ${network_interface_id_dut_2}
    aws ec2 delete-network-interface --network-interface-id ${network_interface_id_pktgen_1}
    aws ec2 delete-network-interface --network-interface-id ${network_interface_id_pktgen_2}
    sleep 5

    # Terminate instances
    aws ec2 terminate-instances --instance-ids ${dut_instance_id} ${pktgen_instance_id} > /dev/null
    # Wait 60s to let the AWS clean all the resources
    sleep 60
    log "AWS Resources cleaned"
}


# ---------------------
# Param: instance id
# ---------------------
get_instance_info() {
    local instance_id=$1
    local target=$2
    local instance_full=$(aws ec2 describe-instances --instance-id ${instance_id} --output json --no-paginate)

    case ${target} in 
        state)
            local state=$(echo ${instance_full} | fx .'["Reservations"][0]["Instances"][0]["State"]["Name"]')
            echo ${state}
            ;;
        public_dns)
            local public_dns=$(echo ${instance_full} | fx .'["Reservations"][0]["Instances"][0]["PublicDnsName"]')
            echo ${public_dns}
            ;;
        *)
            echo ""
            ;;
    esac
}

# -------------------
# Params: command
# -------------------
run_cmd_dut() {
    local cmd=$*
    log "Run on DUT: ${cmd}"
    ssh -i ${KEY_FILE_PATH} ec2-user@${dut_instance_public_dns} -o "StrictHostKeyChecking no" "${cmd}"
    return $?
}

# -------------------
# Param: command
# -------------------
run_cmd_pktgen() {
    local cmd=$*
    log "Run on PKTGEN: ${cmd}"
    ssh -i ${KEY_FILE_PATH} ec2-user@${pktgen_instance_public_dns} -o "StrictHostKeyChecking no" "${cmd}"
    return $?
}

# -----------------
# Params: 1: Host, 2: filename
# -----------------
upload_to_ec2() {
    local host=$1
    local file=$2
    scp -i ${KEY_FILE_PATH} ${file} ec2-user@${host}:/home/ec2-user/
}

# -----------------
# Params: filename (must under DUT's ec2-user home directory)
# -----------------
download_dut_log() {
    local filename=$1
    log "Downloading ${filename} from DUT"
    scp -i ${KEY_FILE_PATH} ec2-user@${dut_instance_public_dns}:/home/ec2-user/${filename} ./tmp/${filename}
}

start_traffic() {
    log "Start traffic on pktgen instance"
    # Get mac and IP address of eth1 on the DUT
    local dut_mac=$(aws ec2 describe-network-interfaces --network-interface-ids ${network_interface_id_dut_1} --output json --no-paginate | fx .'["NetworkInterfaces"][0]["MacAddress"]')
    local dut_ipv4=${IP_ADD_DUT_1}

    log "DUT network info: MAC-${dut_mac}, IP-${dut_ipv4}"

    run_cmd_pktgen "nohup timeout 120 /usr/libexec/ksamples/pktgen/pktgen_sample03_burst_single_flow.sh -i eth1 -m ${dut_mac} -d ${dut_ipv4} -t 4 > traffic.out 2> traffic.err < /dev/null &"
    sleep 5
}

# ------------
# Params:
# 1. XDP action, XDP_PASS, XDP_DROP...
# 2. XDP load mode, native/skb
# ------------
run_xdp_basic_test() {
    local action=$1
    local mode=$2
    # Start traffic firstly
    start_traffic

    if [[ ${mode} == "skb" ]];then
        local load_mode="-S"
    else
        local load_mode=""
    fi
    
    log "Start XDP program on dut instance with action ${action} in ${mode} load mode."
    run_cmd_dut "sudo nohup timeout 80 /usr/libexec/ksamples/bpf/xdp_rxq_info --dev eth1 --action ${action} ${load_mode} > ~/${action}_${mode}.log &"
    sleep 40
    download_dut_log "${action}_${mode}.log"
}

run_xdp_redirect_test() {
    local index_1=$1
    local index_2=$2
    local redirect_map=$3
}

run_xdp_redirect_cpu_test() {
    local cpu1=$1
    local cpu2=$2
    local prog=$3
}

check_test_log() {
    local log_path=$1
    local pps=$(grep -e "^XDP-RX" ${log_path} | awk '{print $4}' | sort -nu | tail -n1 | sed 's/,//g')
    local test_name=$(echo ${log_path} | awk -F '/' '{print $2}' | sed 's/.log//g')
    if ((pps > 400000));then
        log "${test_name} Max PPS: ${pps} [GOOD]"
    else
        log "${test_name} Max PPS: ${pps} [BAD]"
    fi
}

# ------------------Shared Library End----------------------------

START_TIME=$(date +%s)

# Disable AWS cli pager
AWS_PAGER=""

# Clean AWS resource if exit
trap clean_resource EXIT

# Change permission of pem key file

chmod 400 ${KEY_FILE_PATH}

# Confirm test params
echo "Do you want to run the test with below params?"
echo ""
echo "KEY_PAIR_NAME=${KEY_PAIR_NAME}"
echo "MGMT_SG_GROUP=${MGMT_SG_GROUP}"
echo "TEST_SG_GROUP=${TEST_SG_GROUP}"
echo "MGMT_SUBNET_ID=${MGMT_SUBNET_ID}"
echo "TEST_SUBNET_ID=${TEST_SUBNET_ID}"
echo "IP_ADD_PKTGEN_1=${IP_ADD_PKTGEN_1}"
echo "IP_ADD_DUT_1=${IP_ADD_DUT_1}"
echo "IP_ADD_PKTGEN_2=${IP_ADD_PKTGEN_2}"
echo "IP_ADD_DUT_2=${IP_ADD_DUT_2}"
echo "KEY_FILE_PATH=${KEY_FILE_PATH}"
echo "INSTANCE_TYPE=${INSTANCE_TYPE}"
echo "PROXY_URL=${PROXY_URL}"
echo "-----------------AMI Build------------------"
echo "DEFAULT_AMI_ID=${DEFAULT_AMI_ID}"

read -p "[yes/no(default)]" confirmation

if ! [[ $confirmation == "yes" ]];then
    echo "exit script."; exit 1
fi


# Install fx tool to operate json
log "Downloading fx tool"
fx --version > /dev/null
if ! [[ $? == 0 ]];then
    if [[ $(uname) == "Darwin" ]];then
        brew install fx
    elif [[ $(uname) == "Linux" ]];then
        wget https://github.com/antonmedv/fx/releases/download/24.0.0/fx_linux_amd64 -O fx
        chmod 755 fx
        mv fx /usr/bin/
    else
        log "Couldn't download fx tool, exit."; exit 1
    fi
fi
log "Done check fx tool"

# Check wget installation
which wget > /dev/null
if ! [[ $? == 0 ]];then
    log "Downloading wget"
    if [[ $(uname) == "Darwin" ]];then
        brew install fx
    elif [[ $(uname) == "Linux" ]];then
        # only on redhat/fedora
        yum install -y wget
    else 
        log "Couldn't download wget, exit"; exit 1
    fi
fi


# Create tmp folder to store logs
mkdir -p tmp

# Build AMI
if [[ ${EXIST_AMI_ID} == "" ]];then
    log "Building AMI on AWS"
    
    # You may have our own way to generate a AMI, use below line to get the ami id.
    # built_ami_id=$(aws ec2 describe-images --filters "Name=name,Values=${BUILD_TAG}" \
    #                                     --output json \
    #                                     --no-paginate | fx .'["Images"][0]["ImageId"]')
    built_ami_id=${DEFAULT_AMI_ID}
else
    built_ami_id=${EXIST_AMI_ID}
fi

log "New AMI ID is ${built_ami_id}"


# Start instance with the built AMI
log "Creating 2 instances with the new AMI"
aws_instance_data=$(aws ec2 run-instances --image-id ${built_ami_id} \
                    --count 2 \
                    --instance-type ${INSTANCE_TYPE} \
                    --key-name ${KEY_PAIR_NAME} \
                    --security-group-ids ${MGMT_SG_GROUP} \
                    --subnet-id ${MGMT_SUBNET_ID} \
                    --placement AvailabilityZone=us-west-2a \
                    --associate-public-ip-address \
                    --output json \
                    --no-paginate)

dut_instance_id=$(echo $aws_instance_data | fx .'["Instances"][0]["InstanceId"]')
pktgen_instance_id=$(echo $aws_instance_data | fx .'["Instances"][1]["InstanceId"]')

log "DUT instance id is ${dut_instance_id}"
log "PKTGEN instance id is ${pktgen_instance_id}"



log "Instance booting"
# instances booting up
while ! [[ $(get_instance_info ${dut_instance_id} state) == "running" ]] && ! [[ $(get_instance_info ${pktgen_instance_id} state) == "running" ]];do
    sleep 5
done

log "Instance booted"


# Get instance public DNS name
dut_instance_public_dns=$(get_instance_info ${dut_instance_id} public_dns)
pktgen_instance_public_dns=$(get_instance_info ${pktgen_instance_id} public_dns)
log "DUT instance public DNS is ${dut_instance_public_dns}"
log "PKTGEN instance public DNS is ${pktgen_instance_public_dns}"

# Create network interface with xdp test security group
log "Creating 4 network interfaces for xdp testing"
xdp_network_port_pktgen_1=$(aws ec2 create-network-interface --subnet-id ${TEST_SUBNET_ID} \
                                 --description xdp-test-port1 \
                                 --groups ${TEST_SG_GROUP} \
                                 --private-ip-address ${IP_ADD_PKTGEN_1} \
                                 --output json \
                                 --no-paginate)

xdp_network_port_dut_1=$(aws ec2 create-network-interface --subnet-id ${TEST_SUBNET_ID} \
                                 --description xdp-test-port2 \
                                 --groups ${TEST_SG_GROUP} \
                                 --private-ip-address ${IP_ADD_DUT_1} \
                                 --output json \
                                 --no-paginate)
xdp_network_port_pktgen_2=$(aws ec2 create-network-interface --subnet-id ${TEST_SUBNET_ID} \
                                 --description xdp-test-port3 \
                                 --groups ${TEST_SG_GROUP} \
                                 --private-ip-address ${IP_ADD_PKTGEN_2} \
                                 --output json \
                                 --no-paginate)

xdp_network_port_dut_2=$(aws ec2 create-network-interface --subnet-id ${TEST_SUBNET_ID} \
                                 --description xdp-test-port4 \
                                 --groups ${TEST_SG_GROUP} \
                                 --private-ip-address ${IP_ADD_DUT_2} \
                                 --output json \
                                 --no-paginate)

network_interface_id_pktgen_1=$(echo $xdp_network_port_pktgen_1| fx .'["NetworkInterface"]["NetworkInterfaceId"]')
network_interface_id_dut_1=$(echo $xdp_network_port_dut_1| fx .'["NetworkInterface"]["NetworkInterfaceId"]')
network_interface_id_pktgen_2=$(echo $xdp_network_port_pktgen_2| fx .'["NetworkInterface"]["NetworkInterfaceId"]')
network_interface_id_dut_2=$(echo $xdp_network_port_dut_2| fx .'["NetworkInterface"]["NetworkInterfaceId"]')

log "pktgen_1 id is: ${network_interface_id_pktgen_1}"
log "dut_1 id is: ${network_interface_id_dut_1}"
log "pktgen_2 id is: ${network_interface_id_pktgen_2}"
log "dut_2 id is: ${network_interface_id_dut_2}"

# Attach network interface to ec2 dut instance
log "Attaching network interface to the instances"
network_attachment_id_dut_1=$(aws ec2 attach-network-interface --network-interface-id "${network_interface_id_dut_1}" \
                                 --instance-id "${dut_instance_id}" \
                                 --device-index 1 \
                                 --output json \
                                 --no-paginate | fx .'["AttachmentId"]')
log "Attached dut_1(${network_interface_id_dut_1}) to dut instance(${dut_instance_id}), IP: ${IP_ADD_DUT_1}"

network_attachment_id_dut_2=$(aws ec2 attach-network-interface --network-interface-id "${network_interface_id_dut_2}" \
                                 --instance-id "${dut_instance_id}" \
                                 --device-index 2 \
                                 --output json \
                                 --no-paginate | fx .'["AttachmentId"]')
log "Attached dut_2(${network_interface_id_dut_2}) to dut instance(${dut_instance_id}), IP: ${IP_ADD_DUT_2}"

# Attach network interface to ec2 pktgen instance
network_attachment_id_pktgen_1=$(aws ec2 attach-network-interface --network-interface-id "${network_interface_id_pktgen_1}" \
                                 --instance-id "${pktgen_instance_id}" \
                                 --device-index 1 \
                                 --output json \
                                 --no-paginate | fx .'["AttachmentId"]')
log "Attached pktgen_1(${network_interface_id_pktgen_1}) to pktgen instance(${pktgen_instance_id}), IP: ${IP_ADD_PKTGEN_1}"

network_attachment_id_pktgen_2=$(aws ec2 attach-network-interface --network-interface-id "${network_interface_id_pktgen_2}" \
                                 --instance-id "${pktgen_instance_id}" \
                                 --device-index 2 \
                                 --output json \
                                 --no-paginate | fx .'["AttachmentId"]')
log "Attached pktgen_2(${network_interface_id_pktgen_2}) to pktgen instance(${pktgen_instance_id}), IP: ${IP_ADD_PKTGEN_2}"

# Pre-test checklist
log "Start pre-test checking, give AWS 150s to calm down."
sleep 150

# Assert I can login to the instances
log "Checking instances login"
run_cmd_dut "echo access dut success!" || err "DUT login check fail."
run_cmd_pktgen "echo access pktgen success!" || err "PKTGEN login check fail."

# Assert the connectivity of XDP test port
log "Checking instances connectivities"
run_cmd_dut "ping -c 3 ${IP_ADD_PKTGEN_1}" || err "Connectivities check fail"
run_cmd_dut "ping -c 3 ${IP_ADD_PKTGEN_2}" || err "Connectivities check fail"
run_cmd_pktgen "ping -c 3 ${IP_ADD_DUT_1}" || err "Connectivities check fail"
run_cmd_pktgen "ping -c 3 ${IP_ADD_DUT_2}" || err "Connectivities check fail"

# Assert the default route is not the XDP test port
log "Checking instances default route"
dut_route_table=$(run_cmd_dut "ip route")
pktgen_route_table==$(run_cmd_pktgen "ip route")

echo "${dut_route_table}" | grep -e "^default *. ${IP_ADD_DUT_1} metric 100" && err "Default route check fail on DUT"
echo "${dut_route_table}" | grep -e "^default *. ${IP_ADD_DUT_2} metric 100" && err "Default route check fail on DUT"
echo "${pktgen_route_table}" | grep -e "^default *. ${IP_ADD_PKTGEN_1} metric 100" && err "Default route check fail on PKTGEN"
echo "${pktgen_route_table}" | grep -e "^default *. ${IP_ADD_PKTGEN_2} metric 100" && err "Default route check fail on PKTGEN"

# Assert the driver is ena and log it's firmware version
log "Checking the instance network interface driver"
dut_nic_info_1=$(run_cmd_dut "ethtool -i eth1")
dut_nic_info_2=$(run_cmd_dut "ethtool -i eth2")

echo "${dut_nic_info_1}" | grep -q "driver: ena" || err "ENA driver check fail."
echo "${dut_nic_info_2}" | grep -q "driver: ena" || err "ENA driver check fail."

# Pre-test check done
log "Pre-test check done, all good."

# Download kernel-selftests-internal and kernel-modules-internal to local and upload them to ec2
uname_r=$(run_cmd_dut "uname -r")
kernel_version=$(echo "${uname_r}"| awk -F '-' '{print $1}')
arch=$(run_cmd_dut "arch")
minor=$(echo ${uname_r} | awk -F '-' '{print $2}' | sed "s/.${arch}//g")
selftests_internal_url="" # The url you can get the kernel-selftests build
modules_internal_url="" # The url you can get the kernel-modules

log "Downloading kernel-selftests-internal and kernel-modules-internal rpm to local"
ls kernel-selftests-internal-${uname_r}.rpm || wget "${selftests_internal_url}"
ls kernel-modules-internal-${uname_r}.rpm || wget "${modules_internal_url}"


log "Uploading rpms to instances"
upload_to_ec2 "${dut_instance_public_dns}" "kernel-selftests-internal-${uname_r}.rpm"
upload_to_ec2 "${pktgen_instance_public_dns}" "kernel-selftests-internal-${uname_r}.rpm"
upload_to_ec2 "${dut_instance_public_dns}" "kernel-modules-internal-${uname_r}.rpm"
upload_to_ec2 "${pktgen_instance_public_dns}" "kernel-modules-internal-${uname_r}.rpm"

log "Installing rpms on instances"
run_cmd_dut "sudo yum install -yq bpftool && sudo rpm -ivh kernel-selftests-internal-${uname_r}.rpm kernel-modules-internal-${uname_r}.rpm"
run_cmd_pktgen "sudo yum install -yq bpftool && sudo rpm -ivh kernel-selftests-internal-${uname_r}.rpm kernel-modules-internal-${uname_r}.rpm"

log "Checking rpms present on instances"
run_cmd_dut "rpm -q kernel-selftests-internal kernel-modules-internal" || err "instance missing required rpms"
run_cmd_pktgen "rpm -q kernel-selftests-internal kernel-modules-internal" || err "instance missing required rpms"


# XDP special configuration
run_cmd_dut "sudo ulimit -l unlimited;sudo ip link set dev eth1 mtu 3498;sudo ip link set eth2 mtu 3498;sudo ethtool -L eth1 combined 2;sudo ethtool -L eth2 combined 2"
run_cmd_pktgen "sudo ulimit -l unlimited;sudo ip link set dev eth1 mtu 3498;sudo ip link set eth2 mtu 3498;sudo ethtool -L eth1 combined 2;sudo ethtool -L eth2 combined 2"

# Run XDP basic testing, including XDP_PASS/XDP_DROP/XDP_TX/XDP_ABORTED action
run_xdp_basic_test XDP_PASS native
run_xdp_basic_test XDP_DROP native
run_xdp_basic_test XDP_ABORTED native
run_xdp_basic_test XDP_TX native

run_xdp_basic_test XDP_PASS skb
run_xdp_basic_test XDP_DROP skb
run_xdp_basic_test XDP_ABORTED skb
run_xdp_basic_test XDP_TX skb


# Check the pps of the test logs
log "----------------------Test-Results-Check-------------------------"
check_test_log tmp/XDP_ABORTED_native.log 
check_test_log tmp/XDP_DROP_native.log
check_test_log tmp/XDP_PASS_native.log
check_test_log tmp/XDP_TX_native.log

check_test_log tmp/XDP_ABORTED_skb.log
check_test_log tmp/XDP_DROP_skb.log
check_test_log tmp/XDP_PASS_skb.log
check_test_log tmp/XDP_TX_skb.log
log "-----------------------------Done---------------------------------"
