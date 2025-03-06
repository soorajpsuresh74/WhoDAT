import string
import joblib
import nltk
import pandas as pd
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from core.models.Resository.file_destinations import FileManagement  # Ensure correct path

# Download necessary NLTK data
nltk.download('stopwords')

# Global Variables
stemmer = PorterStemmer()
stopwords_set = set(stopwords.words('english'))


def load_dataset():
    """Load dataset from CSV file."""
    df = pd.read_csv(FileManagement.SPAM_HAM_DATASET)
    df['text'] = df['text'].apply(lambda x: x.replace('\r\n', ' '))  # Remove newlines
    return df


def preprocess_text(text):
    """Clean and preprocess a given text."""
    text = text.lower().translate(str.maketrans('', '', string.punctuation)).split()
    text = [stemmer.stem(word) for word in text if word not in stopwords_set]
    return " ".join(text)


def preprocess_corpus(df):
    """Preprocess the entire dataset's text column."""
    return [preprocess_text(text) for text in df['text']]


def train_model(X, y):
    """Train a RandomForestClassifier and return the trained model."""
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    accuracy = clf.score(X_test, y_test)
    print(f"Model Accuracy: {accuracy:.4f}")
    return clf, X_train, X_test, y_train, y_test


def save_model(model, vectorizer):
    """Save trained model and vectorizer."""
    joblib.dump(model, r"core/models/SavedModels/spam_ham_classifier.pkl")
    joblib.dump(vectorizer, r"core/models/SavedModels/tfidf_vectorizer_spam.pkl")


def load_model():
    """Load trained model and vectorizer."""
    clf = joblib.load(r"core/models/SavedModels/spam_ham_classifier.pkl")
    vectorizer = joblib.load(r"core/models/SavedModels/tfidf_vectorizer_spam.pkl")
    return clf, vectorizer


def email_to_spam_ham(email_text):
    """Classify an email as spam or ham."""
    clf, vectorizer = load_model()
    processed_text = preprocess_text(email_text)
    X_email = vectorizer.transform([processed_text])
    prediction = clf.predict(X_email)[0]
    return "Spam" if prediction == 1 else "Ham"



