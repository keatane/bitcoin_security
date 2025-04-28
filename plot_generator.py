import csv
import matplotlib.pyplot as plt

def generate_histogram(deltas):
    if deltas:
        plt.figure(figsize=(10, 6))
        plt.hist(deltas, bins=1000, edgecolor='black')
        plt.title('Histogram of Delta Values')
        plt.xlabel('Delta (seconds)')
        plt.ylabel('Frequency')
        plt.xlim(0, 3500)
        plt.grid(True)
        plt.savefig("plot.png")
        plt.show()
    else:
        print("No delta values available to plot.")

def extract_deltas_and_ips_from_csv(filename):
    deltas = []
    try:
        with open(filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                try:
                    delta_value = float(row['delta'])
                    deltas.append(delta_value)
                    if 2900 <= delta_value <= 3100:  # delta around 3000 (+/- 100 seconds tolerance)
                        ipsrc = row.get('ipsrc', 'Unknown')
                        print(f"Delta ~3000 detected: IP Source = {ipsrc}, Delta = {delta_value}")
                except (ValueError, KeyError):
                    # Skip rows where 'delta' is missing or not a number
                    continue
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    return deltas

if __name__ == "__main__":
    filename = "connection_times.csv"  # Change this to your CSV filename
    deltas = extract_deltas_and_ips_from_csv(filename)
    generate_histogram(deltas)

