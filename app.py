import os
import json
import uuid
from datetime import datetime
from decimal import Decimal

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

import boto3
from botocore.exceptions import ClientError
from groq import Client
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ==================== LOAD ENV ====================
load_dotenv()

# ==================== FLASK APP ====================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-this-in-production")

# Configure CORS to allow credentials from React frontend on port 5000
CORS(app, 
     supports_credentials=True,
     origins=["http://localhost:5000", "http://127.0.0.1:5000", "http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001"],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
     # ==================== EMAIL CONFIGURATION ====================
EMAIL = os.getenv('EMAIL')
APP_PASSWORD = os.getenv('APP_PASSWORD')

# ==================== GROQ CLIENT ====================
# ==================== GROQ CLIENT ====================
try:
    groq_client = Client(
        api_key=os.getenv("GROQ_API_KEY")
    )
    print("✅ Groq client initialized successfully")
except Exception as e:
    print(f"❌ Groq client initialization failed: {e}")
    groq_client = None


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
    print("✅ DynamoDB connected successfully")
except Exception as e:
    print(f"❌ DynamoDB connection failed: {e}")
    users_table = None
    quiz_table = None

# ==================== IN-MEMORY QUIZ SESSIONS ====================
quiz_sessions = {}

# ==================== HELPER FUNCTIONS ====================

def validate_email(email):
    """Basic email validation"""
    return "@" in email and "." in email and len(email) > 5

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, "Valid"

def is_logged_in():
    """Check if user is logged in"""
    return "user_id" in session and "email" in session
# ==================== EMAIL HELPER FUNCTION ====================
def send_quiz_results_email(user_email, user_name, quiz_data):
    """
    Send quiz results to user via email
    
    Args:
        user_email: User's email address
        user_name: User's name
        quiz_data: Dictionary containing score, topic, review, etc.
    
    Returns:
        Tuple (success: bool, message: str)
    """
    try:
        if not EMAIL or not APP_PASSWORD:
            print("❌ Email credentials not configured")
            return False, "Email service not configured"
        
        # Extract quiz data
        score = quiz_data.get('score', 0)
        total = quiz_data.get('total_questions', 0)
        percentage = quiz_data.get('percentage', 0)
        topic = quiz_data.get('topic', 'Unknown')
        review = quiz_data.get('review', [])
        
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'Quiz Results - {topic}'
        msg['From'] = EMAIL
        msg['To'] = user_email
        
        # Plain text version
        text_content = f"""
Hello {user_name},

Here are your quiz results for: {topic}

Score: {score}/{total} ({percentage}%)

Detailed Review:
{'=' * 50}
"""
        
        for i, item in enumerate(review, 1):
            status = "✓ CORRECT" if item['is_correct'] else "✗ INCORRECT"
            text_content += f"""
Question {i}: {item['question']}

Options:
A) {item['options'][0]}
B) {item['options'][1]}
C) {item['options'][2]}
D) {item['options'][3]}

Your Answer: {item['your_answer']}
Correct Answer: {item['correct_answer']}
Status: {status}

{'-' * 50}
"""
        
        text_content += """

Thank you for taking the quiz!

Best regards,
Quiz Application Team
"""
        
        # HTML version with better formatting
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }}
        .score-box {{
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .score-box h2 {{
            margin: 0 0 10px 0;
            color: #667eea;
        }}
        .question-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .question-number {{
            color: #667eea;
            font-weight: bold;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .question-text {{
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #2c3e50;
        }}
        .options {{
            margin: 15px 0;
        }}
        .option {{
            padding: 10px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 5px;
            font-size: 14px;
        }}
        .answer-section {{
            margin-top: 15px;
            padding: 15px;
            border-radius: 5px;
        }}
        .correct {{
            background: #d4edda;
            border-left: 4px solid #28a745;
        }}
        .incorrect {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
        }}
        .answer-label {{
            font-weight: bold;
            margin-right: 10px;
        }}
        .footer {{
            margin-top: 40px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 5px;
            text-align: center;
            color: #6c757d;
            font-size: 14px;
        }}
        .percentage {{
            font-size: 36px;
            font-weight: bold;
            color: {'#28a745' if percentage >= 70 else '#ffc107' if percentage >= 50 else '#dc3545'};
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎓 Quiz Results</h1>
        <p>Hello {user_name}!</p>
    </div>
    
    <div class="score-box">
        <h2>📊 Your Performance</h2>
        <p><strong>Topic:</strong> {topic}</p>
        <p><strong>Score:</strong> {score} out of {total} questions</p>
        <p class="percentage">{percentage}%</p>
    </div>
    
    <h2 style="color: #667eea; margin-top: 30px;">📝 Detailed Review</h2>
"""
        
        # Add each question to HTML
        for i, item in enumerate(review, 1):
            is_correct = item['is_correct']
            status_class = "correct" if is_correct else "incorrect"
            status_icon = "✓" if is_correct else "✗"
            status_text = "CORRECT" if is_correct else "INCORRECT"
            
            html_content += f"""
    <div class="question-card">
        <div class="question-number">Question {i}</div>
        <div class="question-text">{item['question']}</div>
        
        <div class="options">
            <div class="option"><strong>A)</strong> {item['options'][0]}</div>
            <div class="option"><strong>B)</strong> {item['options'][1]}</div>
            <div class="option"><strong>C)</strong> {item['options'][2]}</div>
            <div class="option"><strong>D)</strong> {item['options'][3]}</div>
        </div>
        
        <div class="answer-section {status_class}">
            <div><span class="answer-label">Your Answer:</span> {item['your_answer']}</div>
            <div><span class="answer-label">Correct Answer:</span> {item['correct_answer']}</div>
            <div style="margin-top: 10px; font-weight: bold;">{status_icon} {status_text}</div>
        </div>
    </div>
"""
        
        html_content += """
    <div class="footer">
        <p>Thank you for taking the quiz!</p>
        <p>Keep learning and improving! 🚀</p>
        <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">
        <p style="font-size: 12px;">This email was sent from the Quiz Application System</p>
    </div>
</body>
</html>
"""
        
        # Attach both versions
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email using Gmail SMTP
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL, APP_PASSWORD)
            server.send_message(msg)
        
        print(f"✅ Email sent successfully to {user_email}")
        return True, "Email sent successfully"
        
    except Exception as e:
        print(f"❌ Error sending email: {str(e)}")
        return False, f"Failed to send email: {str(e)}"

# ==================== AUTHENTICATION API ====================

@app.route("/api/signup", methods=["POST", "OPTIONS"])
def signup():
    """Register a new user"""
    if request.method == "OPTIONS":
        return "", 200
    
    try:
        data = request.get_json()
        
        # Extract and validate fields
        name = data.get("name", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        phone = data.get("phone", "").strip()
        age = data.get("age")
        gender = data.get("gender", "").strip()
        
        # Check all fields are present
        if not all([name, email, password, phone, age, gender]):
            return jsonify({"error": "All fields are required"}), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400
        
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({"error": message}), 400
        
        # Validate age
        try:
            age = int(age)
            if age < 13 or age > 120:
                return jsonify({"error": "Age must be between 13 and 120"}), 400
        except ValueError:
            return jsonify({"error": "Invalid age"}), 400
        
        # Check if email already exists
        try:
            response = users_table.get_item(Key={"email": email})
            if "Item" in response:
                return jsonify({"error": "Email already registered"}), 409
        except Exception as e:
            print(f"DynamoDB error: {e}")
            return jsonify({"error": "Database error"}), 500
        
        # Hash password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Create user in database
        user_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        
        users_table.put_item(
            Item={
                "email": email,
                "user_id": user_id,
                "password_hash": password_hash,
                "name": name,
                "phone": phone,
                "age": age,
                "gender": gender,
                "created_at": timestamp,
                "last_login": None,
                "is_active": True
            }
        )
        
        return jsonify({
            "message": "Signup successful! Please login.",
            "user_id": user_id
        }), 201
        
    except Exception as e:
        print(f"Signup error: {e}")
        return jsonify({"error": "An error occurred during signup"}), 500


@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    """Login existing user"""
    if request.method == "OPTIONS":
        return "", 200
    
    try:
        data = request.get_json()
        
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        # Get user from database
        try:
            response = users_table.get_item(Key={"email": email})
            
            if "Item" not in response:
                return jsonify({"error": "Invalid email or password"}), 401
            
            user = response["Item"]
            
            # Check if account is active
            if not user.get("is_active", True):
                return jsonify({"error": "Account is deactivated"}), 403
            
            # Verify password
            if not check_password_hash(user["password_hash"], password):
                return jsonify({"error": "Invalid email or password"}), 401
            
            # Create session
            session["user_id"] = user["user_id"]
            session["email"] = user["email"]
            session["name"] = user["name"]
            session.permanent = True
            
            # Update last login
            users_table.update_item(
                Key={"email": email},
                UpdateExpression="SET last_login = :timestamp",
                ExpressionAttributeValues={
                    ":timestamp": datetime.utcnow().isoformat()
                }
            )
            
            return jsonify({
                "message": "Login successful",
                "user": {
                    "user_id": user["user_id"],
                    "name": user["name"],
                    "email": user["email"]
                }
            }), 200
            
        except Exception as e:
            print(f"DynamoDB error: {e}")
            return jsonify({"error": "Database error"}), 500
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "An error occurred during login"}), 500


@app.route("/api/logout", methods=["POST", "OPTIONS"])
def logout():
    """Logout user"""
    if request.method == "OPTIONS":
        return "", 200
    
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/api/forgot-password", methods=["POST", "OPTIONS"])
def forgot_password():
    """Verify email exists for password reset"""
    if request.method == "OPTIONS":
        return "", 200
    
    try:
        data = request.get_json()
        email = data.get("email", "").strip().lower()
        
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400
        
        # Check if email exists
        try:
            response = users_table.get_item(Key={"email": email})
            
            if "Item" not in response:
                return jsonify({
                    "message": "Email not found",
                    "email_exists": False
                }), 404
            
            return jsonify({
                "message": "Email verified. You can now reset your password.",
                "email_exists": True,
                "email": email
            }), 200
            
        except Exception as e:
            print(f"DynamoDB error: {e}")
            return jsonify({"error": "Database error"}), 500
            
    except Exception as e:
        print(f"Forgot password error: {e}")
        return jsonify({"error": "An error occurred"}), 500


@app.route("/api/reset-password", methods=["POST", "OPTIONS"])
def reset_password():
    """Reset user password (static flow - no email verification)"""
    if request.method == "OPTIONS":
        return "", 200
    
    try:
        data = request.get_json()
        
        email = data.get("email", "").strip().lower()
        new_password = data.get("new_password", "")
        confirm_password = data.get("confirm_password", "")
        
        # Validate all fields present
        if not all([email, new_password, confirm_password]):
            return jsonify({"error": "All fields are required"}), 400
        
        # Check passwords match
        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400
        
        # Validate password strength
        is_valid, message = validate_password(new_password)
        if not is_valid:
            return jsonify({"error": message}), 400
        
        # Check if user exists
        try:
            response = users_table.get_item(Key={"email": email})
            
            if "Item" not in response:
                return jsonify({"error": "Email not found"}), 404
            
            # Hash new password
            new_password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            
            # Update password in database
            users_table.update_item(
                Key={"email": email},
                UpdateExpression="SET password_hash = :password_hash",
                ExpressionAttributeValues={
                    ":password_hash": new_password_hash
                }
            )
            
            return jsonify({
                "message": "Password reset successful! You can now login with your new password."
            }), 200
            
        except Exception as e:
            print(f"DynamoDB error: {e}")
            return jsonify({"error": "Database error"}), 500
            
    except Exception as e:
        print(f"Reset password error: {e}")
        return jsonify({"error": "An error occurred"}), 500


@app.route("/api/current-user", methods=["GET", "OPTIONS"])
def current_user():
    """Get current logged in user"""
    if request.method == "OPTIONS":
        return "", 200
    
    if not is_logged_in():
        return jsonify({"error": "Not authenticated"}), 401
    
    return jsonify({
        "user_id": session.get("user_id"),
        "name": session.get("name"),
        "email": session.get("email")
    }), 200

# ==================== QUIZ API ====================

@app.route("/api/start-quiz", methods=["POST", "OPTIONS"])
def start_quiz():
    """Start a new quiz - generates random questions using AI"""
    if request.method == "OPTIONS":
        return "", 200
    
    if not is_logged_in():
        return jsonify({"error": "Login required"}), 401
    
    try:
        data = request.get_json()
        
        topic = data.get("topic", "").strip()
        num_questions = int(data.get("num_questions", 5))
        
        if not topic:
            return jsonify({"error": "Topic is required"}), 400
        
        if num_questions < 1 or num_questions > 50:
            return jsonify({"error": "Number of questions must be between 1 and 50"}), 400
        
        # Generate questions using Groq AI
        prompt = f"""Generate exactly {num_questions} multiple choice questions about {topic}.

Return ONLY a valid JSON array with no extra text, explanations, or markdown formatting.
Each question must have exactly 4 options.
The answer must be exactly one letter: A, B, C, or D.

Format:
[
  {{
    "question": "What is the question text?",
    "options": ["First option", "Second option", "Third option", "Fourth option"],
    "answer": "A"
  }}
]

Make the questions diverse and challenging. Do not include any text before or after the JSON array."""
        
        try:
            if not groq_client:
                return jsonify({"error": "AI service not configured"}), 500
            
            response = groq_client.chat.completions.create(
                model="llama3-70b-8192",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            
            # Parse AI response
            content = response.choices[0].message.content.strip()
            
            # Remove markdown code blocks if present
            if content.startswith("```"):
                lines = content.split("\n")
                content = "\n".join([line for line in lines if not line.startswith("```")])
            content = content.strip()
            
            questions = json.loads(content)
            
            # Validate questions format
            if not isinstance(questions, list) or len(questions) == 0:
                raise ValueError("Invalid questions format")
            
            for q in questions:
                if not all(key in q for key in ["question", "options", "answer"]):
                    raise ValueError("Missing required fields in question")
                if len(q["options"]) != 4:
                    q["options"] = q["options"][:4] if len(q["options"]) > 4 else q["options"] + [""] * (4 - len(q["options"]))
                if q["answer"] not in ["A", "B", "C", "D"]:
                    q["answer"] = "A"
            
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            print(f"AI Response: {content}")
            return jsonify({"error": "Failed to parse AI response. Please try again."}), 500
        except Exception as e:
            print(f"Groq API error: {e}")
            return jsonify({"error": f"Failed to generate questions: {str(e)}"}), 500
        
        # Create quiz session
        quiz_id = str(uuid.uuid4())
        
        quiz_sessions[quiz_id] = {
            "user_id": session["user_id"],
            "email": session["email"],
            "name": session["name"],
            "topic": topic,
            "questions": questions,
            "answers": [],
            "current_index": 0,
            "start_time": datetime.utcnow().isoformat()
        }
        
        # Return first question
        first_question = questions[0]
        
        return jsonify({
            "quiz_id": quiz_id,
            "total_questions": len(questions),
            "current_question": 1,
            "question": first_question["question"],
            "options": first_question["options"]
        }), 200
        
    except Exception as e:
        print(f"Start quiz error: {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route("/api/answer/<quiz_id>", methods=["POST", "OPTIONS"])
def submit_answer(quiz_id):
    """Submit answer for current question and get next question"""
    if request.method == "OPTIONS":
        return "", 200
    
    quiz = quiz_sessions.get(quiz_id)
    
    if not quiz:
        return jsonify({"error": "Invalid quiz ID"}), 404
    
    try:
        data = request.get_json()
        answer = data.get("answer", "").strip().upper()
        
        # Validate answer
        if answer not in ["A", "B", "C", "D"]:
            return jsonify({"error": "Invalid answer. Must be A, B, C, or D"}), 400
        
        # Save answer
        quiz["answers"].append(answer)
        quiz["current_index"] += 1
        
        # Check if quiz is complete
        if quiz["current_index"] >= len(quiz["questions"]):
            return jsonify({
                "message": "Quiz completed!",
                "completed": True
            }), 200
        
        # Return next question
        next_question = quiz["questions"][quiz["current_index"]]
        
        return jsonify({
            "message": "Answer saved",
            "completed": False,
            "current_question": quiz["current_index"] + 1,
            "total_questions": len(quiz["questions"]),
            "question": next_question["question"],
            "options": next_question["options"]
        }), 200
        
    except Exception as e:
        print(f"Submit answer error: {e}")
        return jsonify({"error": "An error occurred while submitting answer"}), 500


@app.route("/api/submit/<quiz_id>", methods=["POST", "OPTIONS"])
def submit_quiz(quiz_id):
    """Submit completed quiz and get results"""
    if request.method == "OPTIONS":
        return "", 200
    
    quiz = quiz_sessions.get(quiz_id)
    
    if not quiz:
        return jsonify({"error": "Invalid quiz ID"}), 404
    
    try:
        questions = quiz["questions"]
        user_answers = quiz["answers"]
        
        # Calculate score
        score = 0
        for i, question in enumerate(questions):
            if i < len(user_answers) and user_answers[i] == question["answer"]:
                score += 1
        
        total_questions = len(questions)
        percentage = Decimal(str(round((score / total_questions) * 100, 2)))
        
        # Build detailed review
        review = []
        for i, question in enumerate(questions):
            user_answer = user_answers[i] if i < len(user_answers) else "No answer"
            correct_answer = question["answer"]
            is_correct = user_answer == correct_answer
            
            review.append({
                "question": question["question"],
                "options": question["options"],
                "your_answer": user_answer,
                "correct_answer": correct_answer,
                "is_correct": is_correct
            })
        
        # Save to DynamoDB
        end_time = datetime.utcnow().isoformat()
        
        quiz_result = {
            "query_id": quiz_id,
            "user_id": quiz["user_id"],
            "email": quiz["email"],
            "name": quiz["name"],
            "topic": quiz["topic"],
            "score": score,
            "total_questions": total_questions,
            "percentage": percentage,
            "questions": questions,
            "answers": user_answers,
            "correct_answers": [q["answer"] for q in questions],
            "start_time": quiz["start_time"],
            "end_time": end_time,
            "timestamp": end_time
        }
        
        try:
            if quiz_table is None:
                print("❌ Warning: DynamoDB quiz_table is None - quiz results will not be saved")
            else:
                quiz_table.put_item(Item=quiz_result)
                print(f"✅ Quiz result saved to DynamoDB: {quiz_id}")
        except Exception as e:
            print(f"❌ DynamoDB save error: {e}")
            print(f"Quiz data: {quiz_result}")
            # Continue execution even if DB save fails
        
        # Clean up session
        # ==================== SEND EMAIL WITH RESULTS ====================
        email_data = {
            'score': score,
            'total_questions': total_questions,
            'percentage': float(percentage),
            'topic': quiz["topic"],
            'review': review
        }
        
        email_success, email_message = send_quiz_results_email(
            user_email=quiz["email"],
            user_name=quiz["name"],
            quiz_data=email_data
        )
        
        # Clean up session
        del quiz_sessions[quiz_id]
        
        
        return jsonify({
            "message": "Quiz submitted successfully!",
            "score": score,
            "total_questions": total_questions,
            "percentage": float(percentage),
            "review": review,
            "email_sent": email_success,
            "email_message": email_message
        }), 200
        
    except Exception as e:
        print(f"Submit quiz error: {e}")
        return jsonify({"error": "An error occurred while submitting quiz"}), 500


@app.route("/api/quiz-history", methods=["GET", "OPTIONS"])
def quiz_history():
    """Get all quizzes taken by current user"""
    if request.method == "OPTIONS":
        return "", 200
    
    if not is_logged_in():
        return jsonify({"error": "Login required"}), 401
    
    try:
        if quiz_table is None:
            print("❌ Warning: DynamoDB quiz_table is None - returning empty history")
            return jsonify({
                "history": [],
                "total_quizzes": 0,
                "message": "Database not configured"
            }), 200
        
        # Scan for user's quizzes
        response = quiz_table.scan(
            FilterExpression="user_id = :uid",
            ExpressionAttributeValues={
                ":uid": session["user_id"]
            }
        )
        
        quizzes = response.get("Items", [])
        print(f"✅ Found {len(quizzes)} quiz records for user {session['user_id']}")
        
        # Sort by timestamp (newest first)
        quizzes.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # Return simplified history
        history = []
        for quiz in quizzes:
            history.append({
                "quiz_id": quiz["query_id"],
                "topic": quiz["topic"],
                "score": quiz["score"],
                "total_questions": quiz["total_questions"],
                "percentage": float(quiz.get("percentage", 0)),  # Convert Decimal to float
                "date": quiz["timestamp"]
            })
        
        return jsonify({
            "history": history,
            "total_quizzes": len(history)
        }), 200
        
    except Exception as e:
        print(f"❌ Quiz history error: {e}")
        return jsonify({
            "error": "An error occurred",
            "history": [],
            "total_quizzes": 0
        }), 500

# ==================== UTILITY ROUTES ====================

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    db_status = "disconnected"
    db_details = {}
    
    if users_table and quiz_table:
        try:
            # Test users table
            users_table.table_status
            # Test quiz table  
            quiz_table.table_status
            db_status = "connected"
            db_details = {
                "users_table": users_table.table_name,
                "quiz_table": quiz_table.table_name
            }
        except Exception as e:
            db_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_status,
        "database_details": db_details,
        "ai": "connected" if groq_client else "disconnected"
    }), 200

@app.route("/", methods=["GET"])
def home():
    """Root endpoint"""
    return jsonify({
        "message": "AI Quiz Backend API",
        "version": "1.0.0",
        "endpoints": {
            "auth": ["/api/signup", "/api/login", "/api/logout", "/api/forgot-password", "/api/reset-password"],
            "quiz": ["/api/start-quiz", "/api/answer/<quiz_id>", "/api/submit/<quiz_id>", "/api/quiz-history"],
            "utility": ["/health", "/api/current-user"]
        }
    }), 200

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# ==================== RUN APP ====================

if __name__ == "__main__":
    print("=" * 70)
    print("🚀 AI Quiz Application Backend Starting...")
    print("=" * 70)
    print(f"📍 Server URL: http://127.0.0.1:5001")
    print(f"🏥 Health Check: http://127.0.0.1:5001/health")
    print("=" * 70)
    print("✅ Features:")
    print("   • Dynamic AI-generated questions (random every time)")
    print("   • Secure login/signup with DynamoDB")
    print("   • Static password reset flow (no email)")
    print("   • Quiz history tracking")
    print("   • Session-based authentication")
    print("=" * 70)
    print("📝 API Endpoints:")
    print("   POST /api/signup")
    print("   POST /api/login")
    print("   POST /api/logout")
    print("   POST /api/forgot-password")
    print("   POST /api/reset-password")
    print("   POST /api/start-quiz")
    print("   POST /api/answer/<quiz_id>")
    print("   POST /api/submit/<quiz_id>")
    print("   GET  /api/quiz-history")
    print("   GET  /api/current-user")
    print("=" * 70)
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
