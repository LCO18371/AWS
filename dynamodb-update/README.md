# DynamoDB Table Update Task

## Overview
This folder contains a Bash script (`c1.sh`) that automates the process of updating DynamoDB tables. It handles provisioning throughput changes and updating Global Secondary Indexes (GSI) where applicable. The script reads table names from a file (`tables.txt`) and processes each one individually.

## Script Description

### Purpose
The primary objective of this script is to:
- Update the provisioned throughput (read and write capacity units) for DynamoDB tables.
- Detect and update Global Secondary Indexes (GSI) for each table, if any exist.
- Handle errors gracefully during the update process, such as missing tables or AWS credentials issues.

### Key Features
- **Table File Input**: Reads table names from a `tables.txt` file.
- **Provisioned Throughput Update**: Updates the read and write capacity units for each table to `5`.
- **Global Secondary Index (GSI) Update**: If a table has any GSIs, the script adjusts their read and write capacity units as well.
- **AWS CLI Integration**: Utilizes AWS CLI commands (`aws dynamodb update-table` and `aws dynamodb describe-table`) to interact with DynamoDB.
- **Error Handling**: Handles AWS CLI errors such as invalid tables, missing permissions, or missing global secondary indexes.

## Setup and Prerequisites

### Requirements
- **AWS CLI**: Ensure the AWS CLI is installed and configured with the correct region and credentials.
  - You can install the AWS CLI using:
    ```bash
    pip install awscli
    ```
  - Configure AWS CLI with the required credentials and region:
    ```bash
    aws configure
    ```
- **Bash**: Ensure you are running the script in a Bash environment.
- **DynamoDB Tables**: A list of DynamoDB tables to process should be added to the `tables.txt` file (one table per line).

### Example `tables.txt`

## How to Use the Script

1. **Clone the Repository**: If not done already, clone the repository to your local machine.
   
   ```bash
   git clone https://github.com/yourusername/aws-tasks-repo.git
   cd aws-tasks-repo/dynamodb-update
**Ensure Permissions:** Ensure that the AWS IAM role associated with your credentials has the required permissions to update DynamoDB tables and global secondary indexes.
**RUN THE SCRIPT**
