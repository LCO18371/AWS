#!/bin/bash

# Path to the file containing the list of tables
tables_file="tables.txt"

# AWS Region
region="us-east-2"

# Check if the tables file exists
if [ ! -f "$tables_file" ]; then
  echo "Tables file not found!"
  exit 1
fi

# Loop through each table listed in the file
while IFS= read -r table; do
  echo "Processing table: $table"

  # Check for global secondary indexes
  indexes=$(aws dynamodb describe-table --table-name "$table" --region "$region" --query "Table.GlobalSecondaryIndexes[*].IndexName" --output text 2>&1)
  
  if echo "$indexes" | grep -q "An error occurred"; then
    echo "Error occurred while describing table $table: $indexes"
    continue
  fi

  if [ -n "$indexes" ] && [ "$indexes" != "None" ]; then
    echo "Global secondary indexes found: $indexes"

    # Split the indexes into an array
    IFS=$'\t' read -r -a index_array <<<"$indexes"

    # Create a JSON array for the --global-secondary-index-updates parameter
    gsi_updates="["

    for index in "${index_array[@]}"; do
      gsi_updates="$gsi_updates{\"Update\":{\"IndexName\":\"$index\",\"ProvisionedThroughput\":{\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}}},"
    done

    # Remove trailing comma and close the JSON array
    gsi_updates="${gsi_updates%,}]"

    # Run the update command with GSI updates
    update_result=$(aws dynamodb update-table \
      --table-name "$table" \
      --region "$region" \
      --billing-mode PROVISIONED \
      --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
      --global-secondary-index-updates "$gsi_updates" 2>&1)

    if echo "$update_result" | grep -q "An error occurred"; then
      echo "Error occurred while updating table $table: $update_result"
    fi

  else
    echo "No global secondary indexes found for table $table."

    # Run the update command without GSI updates
    update_result=$(aws dynamodb update-table \
      --table-name "$table" \
      --region "$region" \
      --billing-mode PROVISIONED \
      --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 2>&1)

    if echo "$update_result" | grep -q "An error occurred"; then
      echo "Error occurred while updating table $table: $update_result"
    fi
  fi

  echo "Finished processing table: $table"
  echo "-----------------------------"
done < "$tables_file"

