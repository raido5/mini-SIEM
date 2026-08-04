from pathlib import Path

import joblib

from mini_siem.datasets import (
    load_dataset,
    split_features_target,
    make_train_test_split,
)
from mini_siem.models.logistic_regression import build_model

def main():
    df = load_dataset("data/processed/features_v1.csv")
    x,y = split_features_target(df)
    lr = build_model()
    X_train, X_test, y_train, y_test = make_train_test_split(x,y)
    lr.fit(X_train,y_train)
    model_path = Path("models/logistic_regression/model.joblib")
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(lr, model_path)


if __name__ == "__main__":

    main()