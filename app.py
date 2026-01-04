import os
import json
import uuid
from datetime import datetime

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

import boto3
import smtplib
from email.mime.text import MIMEText

from openai import OpenAI

# ==================== LOAD ENV ====================
load_dotenv()

# ==================== FLASK APP ====================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

CORS(
    app,
    supports_credentials=True,
    origins=["*"],
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"]
)

# ==================== ROOT (FIXES 404) ====================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "Backend is running",
        "service": "Quiz App API"
    })

# ==================== EMAIL CONFIG ====================
EMAIL = os.getenv("EMAIL")
APP_PASSWORD = os.getenv("APP_PASSWORD")

# ==================== OPENAI CLIENT ====================
try:
    openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    print("✅ OpenAI client initialized")
except Exception as e:
    print("❌ OpenAI init failed:", e)
    openai_client = None

# ==================== DYNAMODB ====================
try:
    dynamodb = boto3.resource(
        "dynamodb",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )
    users_table = dynamodb.Table("QuizUsers")
    quiz_table = dynamodb.Table(os.getenv("DYNAMODB_TABLE_NAME", "quizz"))
    print("✅ DynamoDB connected")
except Exception as e:
    print("❌ DynamoDB error:", e)
    users_table = None
    quiz_table = None

# ==================== IN-MEMORY QUIZ ====================
quiz_sessions = {}

# ==================== HELPERS ====================
def is_logged_in():
    return "user_id" in session

# ==================== EMAIL SENDER ====================
def send_email(to_email, subject, body):
    try:
        msg = MIMEText(body)
        msg["From"] = EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL, APP_PASSWORD)
            server.send_message(msg)

        return True
    except Exception as e:
        print("❌ Email error:", e)
        return False

# ==================== AUTH ====================
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.json
    email = data["email"].lower()

    if users_table.get_item(Key={"email": email}).get("Item"):
        return jsonify({"error": "Email exists"}), 409

    users_table.put_item(Item={
        "email": email,
        "user_id": str(uuid.uuid4()),
        "name": data["name"],
        "password": generate_password_hash(data["password"]),
        "created_at": datetime.utcnow().isoformat()
    })

    return jsonify({"message": "Signup success"})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    user = users_table.get_item(Key={"email": data["email"].lower()}).get("Item")

    if not user or not check_password_hash(user["password"], data["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user["user_id"]
    session["email"] = user["email"]
    session["name"] = user["name"]

    return jsonify({"message": "Login success"})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

# ==================== QUIZ ====================
@app.route("/api/start-quiz", methods=["POST"])
def start_quiz():
    if not is_logged_in():
        return jsonify({"error": "Login required"}), 401

    if not openai_client:
        return jsonify({"error": "AI service unavailable"}), 503

    data = request.json
    topic = data["topic"]
    count = int(data.get("num_questions", 5))

    prompt = f"""
Generate exactly {count} MCQs on {topic}.
Return ONLY JSON:
[
  {{
    "question": "...",
    "options": ["A","B","C","D"],
    "answer": "A"
  }}
]
"""

    response = openai_client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )

    questions = json.loads(response.choices[0].message.content)

    quiz_id = str(uuid.uuid4())
    quiz_sessions[quiz_id] = {
        "questions": questions,
        "answers": [],
        "user": session["email"]
    }

    return jsonify({
        "quiz_id": quiz_id,
        "question": questions[0]["question"],
        "options": questions[0]["options"]
    })

@app.route("/api/answer/<quiz_id>", methods=["POST"])
def answer(quiz_id):
    quiz = quiz_sessions.get(quiz_id)
    if not quiz:
        return jsonify({"error": "Quiz not found"}), 404

    quiz["answers"].append(request.json["answer"])
    idx = len(quiz["answers"])

    if idx >= len(quiz["questions"]):
        return jsonify({"completed": True})

    q = quiz["questions"][idx]
    return jsonify({"question": q["question"], "options": q["options"]})

@app.route("/api/submit/<quiz_id>", methods=["POST"])
def submit(quiz_id):
    quiz = quiz_sessions.pop(quiz_id, None)
    if not quiz:
        return jsonify({"error": "Quiz not found"}), 404

    score = sum(
        1 for i, q in enumerate(quiz["questions"])
        if quiz["answers"][i] == q["answer"]
    )

    send_email(
        quiz["user"],
        "Quiz Result",
        f"Score: {score}/{len(quiz['questions'])}"
    )

    return jsonify({
        "score": score,
        "total": len(quiz["questions"])
    })

# ==================== HEALTH ====================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# ==================== RUN ====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Running on port {port}")
    app.run(host="0.0.0.0", port=port)
