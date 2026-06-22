import pandas as pd
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

phishing = pd.read_csv("phishing.csv")
legitimate = pd.read_csv("legitimate.csv")

phishing["label"] = 1
legitimate["label"] = 0

data = pd.concat([phishing, legitimate])

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5)
        )
    ),
    (
        "clf",
        LogisticRegression(max_iter=1000)
    )
])

model.fit(data["url"], data["label"])
joblib.dump(model, "trained_url_model.pkl")

print("Model trained successfully")
