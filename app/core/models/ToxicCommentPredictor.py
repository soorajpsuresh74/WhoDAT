import numpy as np
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score

from core.models.Resository.file_destinations import FileManagement

manager = FileManagement()


def train_and_evaluate_toxic_comment_classifier():
    df = pd.read_csv(manager.TRAIN_CSV)
    test = pd.read_csv(manager.TEST_CSV)
    class_names = ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']

    # Initialize TF-IDF Vectorizer
    vec = TfidfVectorizer(
        ngram_range=(1, 6),
        min_df=3, max_df=0.9,
        strip_accents='unicode',
        use_idf=True,
        analyzer='char',
        stop_words='english',
        smooth_idf=True,
        sublinear_tf=True,
        max_features=50000
    )

    X = vec.fit_transform(df['comment_text'])
    test_features = vec.transform(test['comment_text'])

    scores = []
    models = {}
    submission = pd.DataFrame({'id': test['id']})

    for class_name in class_names:
        train_target = df[class_name]
        classifier = LogisticRegression(C=0.1, solver='sag', max_iter=1500)

        cv_score = np.mean(cross_val_score(classifier, X, train_target, cv=3, scoring='roc_auc'))
        scores.append(cv_score)
        print(f'CV score for class {class_name} is {cv_score:.4f}')

        classifier.fit(X, train_target)
        models[class_name] = classifier

        submission[class_name] = classifier.predict_proba(test_features)[:, 1]


    joblib.dump(models, r'core/models/SavedModels/logistic_regression_models.pkl')
    joblib.dump(vec, r'core/models/SavedModels/tfidf_vectorizer_regression.pkl')

    submission.to_csv(r'core/models/SavedModels/submission.csv', index=False)

    print(f'Mean CV score across all classes: {np.mean(scores):.4f}')

    return models, submission, np.mean(scores)

def classify_new_email_to_toxic(email_text):
    """Classifies a new email for toxicity."""

    models = joblib.load(r'core/models/SavedModels/logistic_regression_models.pkl')
    vec = joblib.load(r'core/models/SavedModels/tfidf_vectorizer_regression.pkl') # Load saved vectorizer

    email_features = vec.transform([email_text])

    class_names = ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']

    predictions = {class_name: models[class_name].predict_proba(email_features)[:, 1][0] for class_name in class_names}

    for category, score in predictions.items():
        print(f"{category.capitalize()}: {score:.4f}")

    return predictions

