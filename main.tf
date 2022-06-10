terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}


# Configure the AWS Provider
provider "aws" {
  shared_credentials_file = "%USERPROFILE%\\.aws\\credentials"
  profile                 = "lequanghuy@lequanghuygialai2"
  region                  = "us-east-1"
}

variable "availability_zones" {
  description = "AZs in this region to use"
  default     = ["us-east-1a", "us-east-1d"]
  type        = list(string)
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

#terraform_vpc
resource "aws_vpc" "terraform_vpc" {
  cidr_block = var.vpc_cidr
  tags = {
    Name = "terraform_vpc"
  }
}

variable "subnet_cidrs_public" {
  description = "Subnet CIDRs for public subnets (length must match configured availability_zones)"
  # this could be further simplified / computed using cidrsubnet() etc.
  # https://www.terraform.io/docs/configuration/interpolation.html#cidrsubnet-iprange-newbits-netnum-
  default = ["10.0.1.0/24", "10.0.2.0/24"]
  type    = list(string)
}

#terraform_public-subnet-1
resource "aws_subnet" "terraform_public-subnet-1" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_cidrs_public[0]
  availability_zone = var.availability_zones[0]
  tags = {
    Name = "terraform_public-subnet-1"
  }
}

#terraform_public-subnet-2
resource "aws_subnet" "terraform_public-subnet-2" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = var.subnet_cidrs_public[1]
  availability_zone = var.availability_zones[1]
  tags = {
    Name = "terraform_public-subnet-2"
  }
}

#terraform_private-subnet-1
resource "aws_subnet" "terraform_private-subnet-1" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = var.availability_zones[0]
  tags = {
    Name = "terraform_private-subnet-1"
  }
}

#terraform_private-subnet-2
resource "aws_subnet" "terraform_private-subnet-2" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = var.availability_zones[1]
  tags = {
    Name = "terraform_private-subnet-2"
  }
}

#terraform_trusted-subnet-1
resource "aws_subnet" "terraform_trusted-subnet-1" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = var.availability_zones[0]
  tags = {
    Name = "terraform_trusted-subnet-1"
  }
}

#terraform_trusted-subnet-2
resource "aws_subnet" "terraform_trusted-subnet-2" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = "10.0.6.0/24"
  availability_zone = var.availability_zones[1]
  tags = {
    Name = "terraform_trusted-subnet-2"
  }
}

#terraform_mgmt-subnet-1
resource "aws_subnet" "terraform_mgmt-subnet-1" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = "10.0.7.0/24"
  availability_zone = var.availability_zones[0]
  tags = {
    Name = "terraform_mgmt-subnet-1"
  }
}

#terraform_mgmt-subnet-2
resource "aws_subnet" "terraform_mgmt-subnet-2" {
  vpc_id            = aws_vpc.terraform_vpc.id
  cidr_block        = "10.0.8.0/24"
  availability_zone = var.availability_zones[1]
  tags = {
    Name = "terraform_mgmt-subnet-2"
  }
}

#terraform_default-nw-acl
resource "aws_network_acl" "terraform_default-nw-acl" {
  vpc_id = aws_vpc.terraform_vpc.id
  subnet_ids = [
    aws_subnet.terraform_public-subnet-1.id,
    aws_subnet.terraform_public-subnet-2.id,
    aws_subnet.terraform_private-subnet-1.id,
    aws_subnet.terraform_private-subnet-2.id,
    aws_subnet.terraform_trusted-subnet-1.id,
    aws_subnet.terraform_trusted-subnet-2.id
  ]

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "terraform_default-nw-acl"
  }
}

#terraform_mgmt-nw-acl
resource "aws_network_acl" "terraform_mgmt-nw-acl" {
  vpc_id = aws_vpc.terraform_vpc.id
  subnet_ids = [
    aws_subnet.terraform_mgmt-subnet-1.id,
    aws_subnet.terraform_mgmt-subnet-2.id,
  ]

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0" #TODO: Should fixed IP(s)
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "terraform_mgmt-nw-acl"
  }
}

#terraform_eip
resource "aws_eip" "terraform_eip" {
  vpc = true
}

#terraform_igw
resource "aws_internet_gateway" "terraform_igw" {
  vpc_id = aws_vpc.terraform_vpc.id

  tags = {
    Name = "terraform_igw"
  }
}

#terraform_nat
resource "aws_nat_gateway" "terraform_nat" {
  allocation_id = aws_eip.terraform_eip.id
  subnet_id     = aws_subnet.terraform_public-subnet-1.id

  tags = {
    Name = "terraform_nat"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.terraform_igw]
}

#terraform_public-rtb
resource "aws_route_table" "terraform_public-rtb" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.terraform_igw.id
  }

  tags = {
    Name = "terraform_public-rtb"
  }
}

resource "aws_route_table_association" "public-1" {
  subnet_id      = aws_subnet.terraform_public-subnet-1.id
  route_table_id = aws_route_table.terraform_public-rtb.id
}

resource "aws_route_table_association" "public-2" {
  subnet_id      = aws_subnet.terraform_public-subnet-2.id
  route_table_id = aws_route_table.terraform_public-rtb.id
}

#terraform_private-rtb
resource "aws_route_table" "terraform_private-rtb" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.terraform_nat.id
  }

  tags = {
    Name = "terraform_private-rtb"
  }
}

resource "aws_route_table_association" "private-1" {
  subnet_id      = aws_subnet.terraform_private-subnet-1.id
  route_table_id = aws_route_table.terraform_private-rtb.id
}

resource "aws_route_table_association" "private-2" {
  subnet_id      = aws_subnet.terraform_private-subnet-2.id
  route_table_id = aws_route_table.terraform_private-rtb.id
}

#terraform_trusted-rtb
resource "aws_route_table" "terraform_trusted-rtb" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.terraform_nat.id
  }

  tags = {
    Name = "terraform_trusted-rtb"
  }
}

resource "aws_route_table_association" "trusted-1" {
  subnet_id      = aws_subnet.terraform_trusted-subnet-1.id
  route_table_id = aws_route_table.terraform_trusted-rtb.id
}

resource "aws_route_table_association" "trusted-2" {
  subnet_id      = aws_subnet.terraform_trusted-subnet-2.id
  route_table_id = aws_route_table.terraform_trusted-rtb.id
}

#terraform_mgmt-rtb
resource "aws_route_table" "terraform_mgmt-rtb" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.terraform_igw.id
  }

  tags = {
    Name = "terraform_mgmt-rtb"
  }
}

resource "aws_route_table_association" "mgmt-1" {
  subnet_id      = aws_subnet.terraform_mgmt-subnet-1.id
  route_table_id = aws_route_table.terraform_mgmt-rtb.id
}

resource "aws_route_table_association" "mgmt-2" {
  subnet_id      = aws_subnet.terraform_mgmt-subnet-2.id
  route_table_id = aws_route_table.terraform_mgmt-rtb.id
}

#public sg
resource "aws_security_group" "terraform_public-sg" {
  name        = "Terraform public security group"
  description = "Allow http/https inbound traffic"
  vpc_id      = aws_vpc.terraform_vpc.id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "terraform_public-sg"
  }
}

resource "aws_security_group_rule" "public-sg-https-ingress-rule" {
  type              = "ingress"
  description       = "TLS from VPC"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terraform_public-sg.id
}

resource "aws_security_group_rule" "public-sg-http-ingress-rule" {
  type              = "ingress"
  description       = "TLS from VPC"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terraform_public-sg.id
}

#app sg
resource "aws_security_group" "terraform_app-sg" {
  name        = "Terraform app security group"
  description = "Allow http inbound traffic"
  vpc_id      = aws_vpc.terraform_vpc.id

  ingress {
    description     = "TLS from VPC"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.terraform_public-sg.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "terraform_app-sg"
  }
}

#mgmt sg
resource "aws_security_group" "terraform_mgmt-sg" {
  name        = "Terraform mgmt security group"
  description = "Allow mgmt inbound traffic"
  vpc_id      = aws_vpc.terraform_vpc.id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "terraform_mgmt-sg"
  }
}

resource "aws_security_group_rule" "public-mgmt-ssh-ingress-rule" {
  type              = "ingress"
  description       = "TLS from VPC"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"] #TODO: Should fixed IP(s)F
  security_group_id = aws_security_group.terraform_mgmt-sg.id
}

resource "aws_security_group_rule" "public-mgmt-rdp-ingress-rule" {
  type              = "ingress"
  description       = "TLS from VPC"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.terraform_mgmt-sg.id
}

#db sg
resource "aws_security_group" "terraform_db-sg" {
  name        = "Terraform db security group"
  description = "Allow database inbound traffic"
  vpc_id      = aws_vpc.terraform_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform_db-sg"
  }
}

resource "aws_security_group_rule" "public-db-mysql-app-ingress-rule-1" {
  type                     = "ingress"
  description              = "TLS from VPC"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.terraform_app-sg.id
  security_group_id        = aws_security_group.terraform_db-sg.id
}

resource "aws_security_group_rule" "public-db-mysql-app-ingress-rule-2" {
  type                     = "ingress"
  description              = "TLS from VPC"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.terraform_mgmt-sg.id
  security_group_id        = aws_security_group.terraform_db-sg.id
}

#alb
resource "aws_lb" "terraform_alb" {
  name               = "terraform-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.terraform_public-sg.id]
  subnets            = [aws_subnet.terraform_public-subnet-1.id, aws_subnet.terraform_public-subnet-2.id]

  tags = {
    Environment = "development"
  }
}

#target group
resource "aws_lb_target_group" "terraform_lb-tg" {
  name     = "terraform-lb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.terraform_vpc.id
}

#web_instance
resource "aws_instance" "terraform_web-server" {
  ami                         = "ami-0c02fb55956c7d316" #Amz Linux 2
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.terraform_public-subnet-1.id     #-> Not specify because confict with: network_interface
  vpc_security_group_ids      = [aws_security_group.terraform_public-sg.id] #-> conflict with: network_interface
  key_name                    = "test_key_pair"
  associate_public_ip_address = true
  user_data                   = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo yum install -y https://s3.region.amazonaws.com/amazon-ssm-region/latest/linux_amd64/amazon-ssm-agent.rpm
              sudo yum install httpd -y
              sudo systemctl enable httpd
              sudo systemctl start httpd
              sudo bash -c 'echo Your very first web server > /var/www/html/index.html'
              EOF
  tags = {
    Name = "terraform_web-server"
  }
}

resource "aws_lb_target_group_attachment" "test" {
  target_group_arn = aws_lb_target_group.terraform_lb-tg.arn
  target_id        = aws_instance.terraform_web-server.id
  port             = 80
}

resource "aws_lb_listener" "terraform_alb_to_lb_tg" {
  load_balancer_arn = aws_lb.terraform_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.terraform_lb-tg.arn
  }
}


#mgmt_instance
resource "aws_instance" "terraform_mgmt-server" {
  ami                         = "ami-0c02fb55956c7d316" #Amz Linux 2
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.terraform_mgmt-subnet-1.id     #-> Not specify because confict with: network_interface
  vpc_security_group_ids      = [aws_security_group.terraform_mgmt-sg.id] #-> conflict with: network_interface
  key_name                    = "test_key_pair"
  associate_public_ip_address = true
  user_data                   = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo yum install -y https://s3.region.amazonaws.com/amazon-ssm-region/latest/linux_amd64/amazon-ssm-agent.rpm
              sudo yum install -y https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
              rpm --import https://repo.mysql.com/RPM-GPG-KEY-mysql-2022
              sudo yum install -y mysql-community-client
              EOF
  tags = {
    Name = "terraform_mgmt-server"
  }
}

#rds
resource "aws_db_instance" "terraform_mysql" {
  allocated_storage      = 10
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  name                   = "mydb"
  username               = "foo"
  password               = "foobarbaz"
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.terraform_db-subnet-group.name
  vpc_security_group_ids = [aws_security_group.terraform_db-sg.id]
}

#db subnet group
resource "aws_db_subnet_group" "terraform_db-subnet-group" {
  name       = "main"
  subnet_ids = [aws_subnet.terraform_trusted-subnet-1.id, aws_subnet.terraform_trusted-subnet-2.id]

  tags = {
    Name = "terraform_db-subnet-group"
  }
}
