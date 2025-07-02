import csv
import numpy as np
import matplotlib.pyplot as plt

def extract_deltas_from_csv(filename):
    deltas = []
    try:
        with open(filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                try:
                    delta_value = float(row['duration_s'])
                    deltas.append(delta_value)
                except (ValueError, KeyError):
                    continue
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    return deltas

def compare_histograms_with_averages(file_info):
    plt.figure(figsize=(10, 6))
    bins = np.linspace(0, 12, 100)  # 0 to 12 hours

    for filename, label, color in file_info:
        durations = extract_deltas_from_csv(filename)
        if not durations:
            print(f"No data found in {filename}")
            continue

        durations_hours = [d / 3600 for d in durations]
        durations_min = [d / 60 for d in durations]
        avg_m = np.mean(durations_min)
        print(f"{label}: {len(durations)} connections, Average duration: {avg_m:.2f} min")
        avg_h = np.mean(durations_hours)
        plt.hist(durations_hours, bins=bins, alpha=0.5, label=f'{label} (avg={avg_m:.2f} min)', color=color)
        plt.axvline(avg_h, color=color, linestyle='dashed', linewidth=2)

    plt.xlabel("Duration (hours)")
    plt.ylabel("Frequency")
    plt.legend()
    plt.yscale('log')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("combined_histogram.png")
    plt.show()

if __name__ == "__main__":
    # Define CSVs with labels and colors
    files = [
        ("connection_times_4.csv", "Capture (4 hours)", "blue"),
        ("connection_times_16.csv", "Capture (16 hours)", "red"),
        ("connection_times_3.csv", "Capture (3 days)", "green")
    ]
    compare_histograms_with_averages(files)
