def calculate_average_time(file_path):
    total_time = 0
    count = 0

    with open(file_path, "r") as file:
        for line in file:
            try:
                # Extract the time value (e.g., "0.181541 seconds")
                time_value = float(line.strip().split()[0])  # Get the numeric part
                total_time += time_value
                count += 1
            except ValueError:
                print(f"Skipping invalid line: {line.strip()}")

    # Calculate the average time
    if count > 0:
        average_time = total_time / count
        print(f"Average time to hash all passwords: {average_time:.6f} seconds")
    else:
        print("No valid entries found in the file.")

file = input("Enter the name of the file containing the hash times: ")

calculate_average_time(file)