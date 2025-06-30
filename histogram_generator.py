import csv
import numpy as np
import matplotlib.pyplot as plt

def generate_histogram(durations):
    if durations:
        # Calculate histogram bins and frequencies
        counts, bin_edges = np.histogram(durations, bins=100)

        # Print bin ranges and frequencies
        print("\nTotal Connections:", len(durations))
        print("Histogram Frequencies:")
        for i in range(len(counts)):
            if counts[i] > 0:
                print(f"{bin_edges[i]:.2f} - {bin_edges[i+1]:.2f} s: {counts[i]} connections")

        # Plot histogram
        plt.figure(figsize=(10, 6))
        plt.hist(durations, bins=100, edgecolor="black")
        plt.title("Connection Duration Histogram")
        plt.xlabel("Seconds")
        plt.ylabel("Frequency")
        plt.grid(True)
        plt.savefig("plot.png")
        plt.show()
    else:
        print("No durations to plot.")

def extract_deltas_and_ips_from_csv(filename):
    deltas = []
    try:
        with open(filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                try:
                    delta_value = float(row['duration_s'])
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

