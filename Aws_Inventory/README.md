# Inventory Management Lambda Function

## Overview
This repository contains a Lambda function designed to manage and update inventory records stored in an Excel file on AWS S3. The function utilizes the `boto3` library to interact with S3 and `openpyxl` to manipulate Excel files. It performs operations like checking the existence of specific files, updating resource creation dates, and handling various AWS regions.

## Key Features
- **AWS S3 Integration**: The function connects to a specified S3 bucket to check for and update an Excel file that contains inventory records.
- **Excel File Management**: Uses the `openpyxl` library to read, modify, and update Excel files stored in the S3 bucket.
- **Error Handling**: Comprehensive handling of various AWS and credential-related errors such as missing credentials, client errors, or file non-existence.
- **Multi-Region Support**: Supports inventory updates across multiple AWS regions, including:
  - `us-east-1`
  - `us-west-2`
  - `us-east-2`
  - `ap-south-1`

## Services and Functionality

### 1. **S3 File Check**
The function first checks whether the specified Excel file exists in the S3 bucket. If it does, the inventory update process begins. If not, appropriate error handling is triggered.
- **Bucket Name**: `task-update-excel-for-all-resource`
- **File Key**: `testing1/AllResource8.xlsx`

### 2. **Resource Creation Date Update**
The script includes logic to update the resource creation date in the Excel file based on the presence of the file in the S3 bucket. If the file is found, the current date is updated; otherwise, it logs `NA` for the date.

### 3. **Error Management**
The script is equipped to handle several errors:
- **No Credentials**: Manages errors where AWS credentials are missing or incomplete.
- **Client Errors**: Catches and logs AWS Client errors, particularly issues with file access.
- **S3 File Absence**: Properly handles the case where the specified file is missing in the S3 bucket.

### 4. **Excel File Operations**
If the file exists, the script uses `openpyxl` to open and edit it. This can include:
- Adding new data rows.
- Modifying existing data.
- Saving changes back to S3.

## Setup and Deployment

### Prerequisites
- **AWS Account**: The function requires access to an AWS account with permissions to access S3.
- **S3 Bucket**: The bucket `task-update-excel-for-all-resource` should exist and contain the file `testing1/AllResource8.xlsx`.
- **AWS Lambda**: The Python code should be deployed as an AWS Lambda function, with appropriate IAM roles to allow access to S3.

### Dependencies
- `boto3`: AWS SDK for Python to interact with S3.
- `openpyxl`: Library for reading and writing Excel files.
- **AWS SDK**: Ensure `boto3` is installed in the Lambda environment.
  - You can install it using the following command:
    ```bash
    pip install boto3 openpyxl
    ```

## Usage
Once the Lambda function is deployed, it can be triggered by an event (like an S3 upload or scheduled invocation). The function will:
1. Check if the specified Excel file exists in the S3 bucket.
2. Update the creation date of the resources within the file.
3. Handle any errors that occur during the process.

### Example Workflow
1. **S3 Event Trigger**: A file is uploaded or modified in the S3 bucket, which triggers the Lambda function.
2. **File Processing**: The function opens the Excel file, updates necessary records, and saves it back to the S3 bucket.
3. **Error Logging**: Any errors (like missing files or credentials) are logged for review.

## Troubleshooting
- **Missing File**: Ensure that the `AllResource8.xlsx` file exists in the correct path (`testing1/`) within the S3 bucket.
- **AWS Credentials**: Ensure that the Lambda execution role has the necessary S3 permissions and the environment is configured with the correct credentials.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
