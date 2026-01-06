import pandas as pd
import pickle
from sklearn.model_selection import train_test_split 
from sklearn.naive_bayes import GaussianNB

# Load dataset
df = pd.read_csv("dataset.csv")

# Drop ID column if present
if 'id' in df.columns:
    df = df.drop(columns=['id'])

# Separate features and label
X = df.drop(columns=['Result'])
y = df['Result']

# Convert labels: -1 (phishing), 1 (legit) → 1 phishing, 0 legit
y = y.replace({-1: 1, 1: 0})

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = GaussianNB()
model.fit(X_train, y_train)

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model trained successfully")
