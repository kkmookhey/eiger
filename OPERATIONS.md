# Halcyon Operations (S1 seed)

The **image is the unit of change** — fix code, rebuild the image, redeploy. Never hand-patch a running container.

> **M3 knowledge base is ephemeral (in-process ChromaDB).** Participant-submitted KB entries live only in the web container's memory. A web-container restart (or `docker compose up -d web`) wipes submitted content back to the seeded fixtures — a participant mid-M3 must resubmit their poison. Graded progress is unaffected (it lives in the audit log / external progress store). The embedding model (~80 MB ONNX MiniLM) downloads on first `/api/ask`; for a fully-offline local-LAN deploy, warm it once with internet or bake it into the image.

## Deploy all (local-LAN or cloud host — same images)
    docker compose up -d --build
    docker compose exec ollama ollama pull llama3.1:8b   # first run only

## Health-check who's up
    curl -s localhost:8000/health | jq
    # expect: {"status":"ok","mode":"...","ollama":"up","db":"up"}

## Redeploy after a code fix (rebuild image, keep db/ollama volumes)
    docker compose up -d --build web

_Reset-one-participant and nuke-and-reprovision land in the Ops slice once the per-participant fleet exists. S1 runs a single app instance against shared db + ollama._

---

## AWS single-instance host (proven config — S1)

A single EC2 box runs the whole `docker compose` stack, bootstrapped from the public repo. This is the S1 host; the 22-container fleet is a later Ops slice.

### ⚠️ Hard-won constraints (do not skip)
- **USE AN AMD INSTANCE** (`r6a`/`m6a`), or a non-AMX Intel gen (`r6i`/`m6i`, Ice Lake). **Do NOT use Intel Sapphire-Rapids "i"-suffix families (`r7i`/`m7i`/`c7i`)** — they expose **Intel AMX**, and Ollama's `llama-server` **segfaults on AMX under virtualization** (crashes every model, every Ollama version — not OOM, not a timeout). This cost us a full relaunch.
- **Account quota:** `sara-sales` has a **5-vCPU Standard On-Demand limit** in ap-south-1, so max instance is **4 vCPU** (an 8-vCPU `*.2xlarge` is rejected with `VcpuLimitExceeded`). Request a quota increase (Service Quotas → "Running On-Demand Standard instances") for anything bigger, or for the multi-instance fleet.
- CPU inference of `llama3.1:8b` on 4 vCPU works but is slow (~6 s cold model-load, then a few seconds/reply). Fine for demo/single-user. For a snappy 22-person Day-1, get a **GPU instance** (e.g. `g5.xlarge`, needs a separate "Running On-Demand G" quota) — CUDA also sidesteps the AMX bug.
- Ollama port `11434` is **not** in the security group — only `8000` (app) + `22` (ssh). Keep it that way.

### Proven parameters (account 331145994818, region ap-south-1)
| Thing | Value |
|---|---|
| AWS profile | `sara-sales` |
| Region | `ap-south-1` |
| Instance type | `r6a.xlarge` (AMD, 4 vCPU, 32 GB, ~$0.24/hr) |
| AMI | Ubuntu 24.04 — resolve latest via SSM (below), don't hardcode |
| Key pair | `halcyon-eiger` |
| Security group | inbound tcp `8000` + `22` from `0.0.0.0/0` |
| Disk | 40 GB gp3 |
| Bootstrap | user-data clones `github.com/kkmookhey/eiger`, `docker compose up -d --build`, pulls `llama3.1:8b` |

### Deploy (one-time infra + launch)
```bash
P="--profile sara-sales --region ap-south-1"
AMI=$(aws ssm get-parameter $P --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)
SUBNET=$(aws ec2 describe-subnets $P --filters Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
VPC=$(aws ec2 describe-subnets $P --subnet-ids $SUBNET --query 'Subnets[0].VpcId' --output text)
aws ec2 create-key-pair $P --key-name halcyon-eiger --query KeyMaterial --output text > halcyon-eiger-key.pem && chmod 600 halcyon-eiger-key.pem
SG=$(aws ec2 create-security-group $P --group-name halcyon-eiger-sg --description "Halcyon Eiger lab" --vpc-id $VPC --query GroupId --output text)
aws ec2 authorize-security-group-ingress $P --group-id $SG --ip-permissions \
  IpProtocol=tcp,FromPort=8000,ToPort=8000,IpRanges='[{CidrIp=0.0.0.0/0}]' \
  IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]'
aws ec2 run-instances $P --image-id $AMI --instance-type r6a.xlarge \
  --key-name halcyon-eiger --security-group-ids $SG --subnet-id $SUBNET --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":40,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --user-data file://deploy/aws-userdata.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=halcyon-eiger}]'
# then: aws ec2 describe-instances $P --filters Name=tag:Name,Values=halcyon-eiger Name=instance-state-name,Values=running --query 'Reservations[].Instances[].PublicIpAddress' --output text
# lab comes up at http://<public-ip>:8000/ after ~10-15 min (docker install + build + model pull)
```
The user-data bootstrap script is versioned at `deploy/aws-userdata.sh`.

### Redeploy a code fix to the running box (no relaunch)
```bash
ssh -i halcyon-eiger-key.pem ubuntu@<ip> 'cd /opt/eiger && sudo git pull --ff-only && sudo docker compose up -d --build web'
```

### Teardown
```bash
P="--profile sara-sales --region ap-south-1"
IID=$(aws ec2 describe-instances $P --filters Name=tag:Name,Values=halcyon-eiger Name=instance-state-name,Values=running,pending --query 'Reservations[].Instances[].InstanceId' --output text)
aws ec2 terminate-instances $P --instance-ids $IID
aws ec2 wait instance-terminated $P --instance-ids $IID
aws ec2 delete-security-group $P --group-name halcyon-eiger-sg
aws ec2 delete-key-pair $P --key-name halcyon-eiger
```
Or just **stop** (not terminate) to pause billing while keeping the box: `aws ec2 stop-instances $P --instance-ids $IID`.
