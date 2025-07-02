import pandas as pd
import matplotlib.pyplot as plt


def analyze_connections(csv_path):
    # Load CSV data
    df = pd.read_csv(csv_path)

    # Filter connections with both start and end timestamps
    valid_connections = df.dropna(subset=["timesyn", "timerst_or_fst"])

    # Category 1: No messages exchanged
    no_messages = valid_connections[valid_connections["messages"].isna()]

    # Category 2: Messages exchanged and duration ≤ 2 minutes (120 seconds)
    with_messages = valid_connections[valid_connections["messages"].notna()]
    short_duration = with_messages[with_messages["connection_duration"] < 600]

    # Category 3: Messages exchanged and duration > 2 minutes
    long_duration = with_messages[with_messages["connection_duration"] >= 600]

    # Count entries in each category
    counts = [len(no_messages), len(short_duration), len(long_duration)]
    labels = [
        "TCP Only - No Bitcoin\nmessages exchanged",
        "Ephemeral connections",
        "Active connections",
#        "Bitcoin messages < 10 min",
#        "Bitcoin messages ≥ 10 min",
    ]

    plt.figure(figsize=(8, 8))
    plt.pie(
        counts,
        labels=labels,
        autopct="%1.1f%%",
        startangle=140,
        textprops={"fontsize": 24},
    )
    plt.axis("equal")
    plt.savefig("connections_piechart.png", dpi=300, bbox_inches="tight")
    plt.show()

analyze_connections("connection_times.csv")
