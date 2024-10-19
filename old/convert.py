import csv

# Specify the input .txt file and output .csv file
input_file = 'IDS.txt'  # Replace with your .txt file path
output_file = 'output.csv'

# Open the .txt file and the .csv file
with open(input_file, 'r') as txt_file, open(output_file, 'w', newline='') as csv_file:
    # Create a CSV writer object
    csv_writer = csv.writer(csv_file)

    # Loop through each line in the .txt file
    for line in txt_file:
        # Strip whitespace and split by ';' to get individual fields
        row = line.strip().split(';')
        # Write the row to the CSV file
        csv_writer.writerow(row)

print(f'Conversion complete! CSV saved as {output_file}')
