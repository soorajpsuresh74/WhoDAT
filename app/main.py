import logging
import os.path

import uvicorn
from fastapi import FastAPI
from sklearn.feature_extraction.text import TfidfVectorizer

from core.models.spamMailDetection import load_dataset, train_model, save_model, preprocess_corpus
from core.models.ToxicCommentPredictor import train_and_evaluate_toxic_comment_classifier, classify_new_email_to_toxic
from config import HOST, PORT, PROTOCOL
from routes.email_routes import router as email_router
from routes.attachment_routes import router as attachment_router
from routes.ip_routes import router as ip_router
from routes.url_routes import router as url_router
from routes.website_routes import router as website_router
from routes.dmarc_routes import router as dmarc_router
from routes.whois_routes import router as whois_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = FastAPI()


@app.get("/")
def root():
    return {"message": "Hello from WhoDAT backend!"}


@app.get("/health")
def health():
    return {"status": "healthy"}


if not os.path.exists('core/models/SavedModels/logistic_regression_models.pkl') or not os.path.exists(
        'core/models/SavedModels/tfidf_vectorizer_regression.pkl'):
    print("File not found for the train_and_evaluate_toxic_comment_classifier")
    models, submission, mean_cv_score = train_and_evaluate_toxic_comment_classifier()
    print("File created for the train_and_evaluate_toxic_comment_classifier")

if not os.path.exists('core/models/SavedModels/spam_ham_classifier.pkl') or not os.path.exists(
        'core/models/SavedModels/tfidf_vectorizer_spam.pkl'):
    print("File not found for the spam_ham_classifier")
    df = load_dataset()
    corpus = preprocess_corpus(df)
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(corpus).toarray()
    y = df['label_num']
    clf, _, _, _, _ = train_model(X, y)
    save_model(clf, vectorizer)
    print("File created for the spam_ham_classifier")

email_text_to_classify = "You are a horrible person! I hate you."
predictions = classify_new_email_to_toxic(email_text_to_classify)
print(predictions)

app.include_router(email_router)
app.include_router(attachment_router)
app.include_router(ip_router)
app.include_router(url_router)
app.include_router(website_router)
app.include_router(dmarc_router)
app.include_router(whois_router)

if __name__ == "__main__":
    logging.info(f"Starting server at {PROTOCOL}://{HOST}:{PORT}")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
    # Example usage (if you want to run it directly):



