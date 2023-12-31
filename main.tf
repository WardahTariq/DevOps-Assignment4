terraform {
  required_providers {
    pgp = {
      source = "ekristen/pgp"
    }

    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# configure the AWS Provider
provider "aws" {
  region = var.aws_reg
}

#---TASK 1----

# create an IAM user
resource "aws_iam_user" "terraform_user" {
  name = "terraform-cs423-devops2"   
}

# provide admin policy to the IAM user
resource "aws_iam_user_policy_attachment" "admin_attachment" {
  user       = aws_iam_user.terraform_user.name 
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" 
}

# create IAM user access key
resource "aws_iam_access_key" "terraform_user_key" {
  user = aws_iam_user.terraform_user.name 
}

#create a pgp key for encryption and decryption of password
resource "pgp_key" "user_login_key" {
  name    = aws_iam_user.terraform_user.name
  email   = "wardahtariq38@gmail.com"
  comment = "Generated PGP Key"
}

#create IAM user login profile with password
resource "aws_iam_user_login_profile" "user_login" {
  user                    = aws_iam_user.terraform_user.name
  pgp_key                 = pgp_key.user_login_key.public_key_base64
  password_reset_required = false
}

#decrypt the password
data "pgp_decrypt" "user_password_decrypt" {

  ciphertext          = aws_iam_user_login_profile.user_login.encrypted_password
  ciphertext_encoding = "base64"
  private_key         = pgp_key.user_login_key.private_key
}

data "aws_caller_identity" "current" {}

#----TASK 2-----

#create a VPC
resource "aws_vpc" "devops-assignment-4" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "devops-assignment-4-2"
  }
}

#create two public subnets
resource "aws_subnet" "public_subnets" {
 count             = length(var.public_subnet_cidrs)
 vpc_id            = aws_vpc.devops-assignment-4.id
 cidr_block        = element(var.public_subnet_cidrs, count.index)
 availability_zone = element(var.azs, count.index)
 
 tags = {
   Name = "cs423-devops-public-${count.index + 1}"
 }
}

#create two private subnets
resource "aws_subnet" "private_subnets" {
 count             = length(var.private_subnet_cidrs)
 vpc_id            = aws_vpc.devops-assignment-4.id
 cidr_block        = element(var.private_subnet_cidrs, count.index)
 availability_zone = element(var.azs, count.index)
 
 tags = {
   Name = "cs423-devops-private-${count.index + 1}"
 }
}

#create internet gateway
resource "aws_internet_gateway" "gw" {
 vpc_id = aws_vpc.devops-assignment-4.id
 
 tags = {
   Name = "cs423-devops-IGW"
 }
}

#create a second route table for the public subnets
resource "aws_route_table" "second_rt" {
 vpc_id = aws_vpc.devops-assignment-4.id
 
 route {
   cidr_block = "0.0.0.0/0"
   gateway_id = aws_internet_gateway.gw.id
 }
 
 tags = {
   Name = "devops-assignment-4 rt"
 }
}

#associate the public subnets with the second route table
resource "aws_route_table_association" "public_subnet_asso" {
 count = length(var.public_subnet_cidrs)
 subnet_id      = element(aws_subnet.public_subnets[*].id, count.index)
 route_table_id = aws_route_table.second_rt.id
}

#---TASK 3---

#create security group with inbound rules for port 22, 80
resource "aws_security_group" "web_server_sg" {
 name        = "web-server-security-group"
 description = "Security group for the web server"
  vpc_id      = aws_vpc.devops-assignment-4.id

   ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Terraform security Group"
  }
}

#---TASK 4---

#generate private public key pair
resource "tls_private_key" "terraform_private_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

#save the private key in a file on local machine
resource "local_file" "private_key" {

	content = tls_private_key.terraform_private_key.private_key_pem
	filename = "webserver_key2"
	file_permission = "400"
}

#associate the public key with aws key pair
resource "aws_key_pair" "webserver_key" {
	key_name= "webserver2"
	public_key = tls_private_key.terraform_private_key.public_key_openssh
}

#---TASK 5---

resource "aws_instance" "web_server_instance" {
  ami         = "ami-0c7217cdde317cfec"
  instance_type = "t2.micro"
  subnet_id   = aws_subnet.public_subnets[0].id
  key_name    = aws_key_pair.webserver_key.key_name
  user_data = <<EOF
#!/bin/bash
sudo apt-get update
sudo apt-get install -y apache2
sudo systemctl start apache2
sudo systemctl enable apache2
EOF

  # Assign a public IP address to EC2 instance to access web server
  associate_public_ip_address = true 

  vpc_security_group_ids = [aws_security_group.web_server_sg.id] 

  tags = {
    Name = "Assignment4-EC2-1-2"
  }
}

# resource "aws_instance" "database_instance" {
#   ami         = "ami-0c7217cdde317cfec"
#   instance_type = "t2.micro"
#   subnet_id   = aws_subnet.private_subnets[0].id
#   user_data   = file("${path.module}/user_data2.sh")

#   # No need for associate_public_ip_address in private subnet

#   tags = {
#     Name = "Assignment4-EC2-2-2"
#   }
# } 













# #create a VPC
# resource "aws_vpc" "devops-assignment-4" {
#   cidr_block = "10.0.0.0/16"

#   tags = {
#     Name = "devops-assignment-4"
#   }
# }

# #create Internet gateway
# resource "aws_internet_gateway" "gw" {
#   vpc_id = aws_vpc.devops-assignment-4.id
# }

# #create route table
# resource "aws_route_table" "rt" {
#   vpc_id = aws_vpc.devops-assignment-4.id

#   route {
#     cidr_block = "0.0.0.0/0"
#     gateway_id = aws_internet_gateway.gw.id
#   }

#   route {
#     ipv6_cidr_block        = "::/0"
#     egress_only_gateway_id = aws_internet_gateway.gw.id
#   }

#   tags = {
#     Name = "devops-assignment-4-rt"
#   }
# }

# #create subnet
# resource "aws_subnet" "subnet-1" {
#   vpc_id     = aws_vpc.devops-assignment-4.id
#   cidr_block = "10.0.1.0/24"
#   availability_zone = "us-east-1a"

#   tags = {
#     Name = "subnet-1"
#   }
# }

# #associate subnet with table route
# resource "aws_route_table_association" "assoc" {
#   subnet_id      = aws_subnet.subnet-1.id
#   route_table_id = aws_route_table.rt.id
# }

# #create security group to allow port 22,80,443
# resource "aws_security_group" "sg" {
#   name        = "sg-A4"
#   description = "Allow web traffic"
#   vpc_id      = aws_vpc.devops-assignment-4.id

#   ingress {
#     description      = "HTTPS"
#     from_port        = 443
#     to_port          = 443
#     protocol         = "tcp"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   ingress {
#     description      = "HTTPS"
#     from_port        = 443
#     to_port          = 443
#     protocol         = "tcp"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   ingress {
#     description      = "HTTP"
#     from_port        = 80
#     to_port          = 80
#     protocol         = "tcp"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   ingress {
#     description      = "SSH"
#     from_port        = 22
#     to_port          = 22
#     protocol         = "tcp"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   egress {
#     from_port        = 0
#     to_port          = 0
#     protocol         = "-1"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   tags = {
#     Name = "web_rules"
#   }
# }

# #create ubuntu server

