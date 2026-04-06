from sklearn.ensemble import IsolationForest

def train_model(data):
    model = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42
    )
    model.fit(data)
    return model

def detect_anomalies(model, data):
    predictions = model.predict(data)
    return predictions
