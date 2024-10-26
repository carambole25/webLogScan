import pandas as pd
import matplotlib.pyplot as plt
import json
from datetime import datetime

def gen_graph(file):
    with open(file) as f:
        data = json.load(f)

    df = pd.DataFrame(data).T
    df['date'] = pd.to_datetime(df['date'], format="%d/%b/%Y:%H:%M:%S")

    df = df.sort_values('date')
    df['cumulative_attacks'] = range(1, len(df) + 1)

    plt.figure(figsize=(10, 6))
    plt.plot(df['date'], df['cumulative_attacks'], marker='o', linestyle='-', color='red')
    plt.title("Nombre cumulé d'attaques dans le temps")
    plt.xlabel("Temps")
    plt.ylabel("Nombre cumulé d'attaques")
    plt.grid(True)

    nom = str(datetime.now())+".png"
    plt.savefig(nom)