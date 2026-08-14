import joblib
import pandas as pd
from mini_siem.rules import predict_rule
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


modele= joblib.load("models/logistic_regression/model.joblib")

df=pd.read_csv("data/processed/features_v1.csv")

X = df.drop(columns=["ip", "label"])   

vrais = df["label"]

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

print("=== MODÈLE ML ===")
print(accuracy_score(vrais, predictions))
print(classification_report(vrais, predictions))
print(confusion_matrix(vrais, predictions))

print("=== RULES ===")
print(accuracy_score(vrais, prediction_rules))
print(classification_report(vrais, prediction_rules))
print(confusion_matrix(vrais, prediction_rules))