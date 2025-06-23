from sklearn.ensemble import IsolationForest
import pandas as pd

# Sample normal traffic training data
train_data = pd.DataFrame({
    'requests_per_minute': [10, 12, 15, 20, 8],
    'avg_time_between_requests': [4, 3.5, 4.2, 3.8, 5],
    'unique_user_agents': [1, 2, 1, 3, 2]
})

model = IsolationForest(contamination=0.2, random_state=42)
model.fit(train_data)

def predict_threat(features):
    df = pd.DataFrame([features])
    result = model.predict(df)[0]
    return result == -1  # -1 means anomaly
