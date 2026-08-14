import joblib
import pandas as pd
from mini_siem.rules import predict_rule

modele= joblib.load("models/logistic_regression/model.joblib")

df=pd.read_csv("data/processed/features_v1.csv")

X = df.drop(columns=["ip", "label"])   

#model predictions
predictions = modele.predict(X)
print(predictions)


#baseline predictions
prediction_rules=[]
for index , row in df.iterrows():
    features = row.to_dict()
    label = predict_rule(features)
    prediction_rules.append(label)

print(prediction_rules)

