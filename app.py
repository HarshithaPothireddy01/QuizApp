import os
import json
import uuid
from datetime import datetime
from groq import Groq  # pip install groq
import boto3
from dotenv import load_dotenv

# -------------------- LOAD ENV --------------------
load_dotenv()

# -------------------- CONFIG --------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME")

# -------------------- GROQ CLIENT --------------------
client = Groq(api_key=GROQ_API_KEY)

# -------------------- DYNAMODB --------------------
dynamodb = boto3.resource(
    "dynamodb",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)
quiz_table = dynamodb.Table(DYNAMODB_TABLE_NAME)

# -------------------- QUIZ FUNCTIONS --------------------
def take_quiz():
    # Get user info
    name = input("Enter your name: ")
    email = input("Enter your email: ")

    # Quiz details
    topic = input("Enter quiz topic: ")

    # Validate number of questions
    while True:
        try:
            num_questions = int(input("Number of questions: "))
            if num_questions <= 0:
                print("Please enter a positive number.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")

    # Generate questions using LLM
    prompt = f"""
    Generate {num_questions} multiple-choice questions on {topic}.
    Respond ONLY in valid JSON format like this:
    [
      {{
        "question": "Question text",
        "options": ["A", "B", "C", "D"],
        "answer": "A"
      }}
    ]
    """
    try:
        completion = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": prompt}]
        )
        questions = json.loads(completion.choices[0].message.content)
    except Exception as e:
        print(f"LLM Error: {e}\nUsing sample questions instead.")
        questions = [
            {"question": f"Sample Question {i+1} on {topic}?",
             "options": ["A", "B", "C", "D"],
             "answer": "A"}
            for i in range(num_questions)
        ]

    # Take quiz one question at a time
    user_answers = []
    print("\n--- Quiz Start ---\n")
    for i, q in enumerate(questions):
        print(f"Q{i+1}: {q['question']}")
        for idx, option in enumerate(q['options']):
            print(f"{chr(65+idx)}. {option}")
        ans = input("Your answer (A/B/C/D): ").strip().upper()
        while ans not in ["A", "B", "C", "D"]:
            ans = input("Invalid choice. Please enter A, B, C, or D: ").strip().upper()
        user_answers.append(ans)
        print()

    # Calculate score
    correct_answers = [q['answer'] for q in questions]
    score = sum(1 for u, c in zip(user_answers, correct_answers) if u == c)
    print(f"--- Quiz Completed ---\nYour Score: {score}/{len(questions)}\n")

    # Save attempt in DynamoDB (single entry per attempt)
    quiz_table.put_item(
        Item={
            "query_id": str(uuid.uuid4()),  # unique id for this attempt
            "name": name,
            "email": email,
            "topic": topic,
            "score": score,
            "total_questions": len(questions),
            "timestamp": datetime.utcnow().isoformat(),
            "answers": user_answers,
            "correct_answers": correct_answers
        }
    )
    print("Your quiz attempt has been saved in DynamoDB.\n")

# -------------------- MAIN --------------------
if __name__ == "__main__":
    print("=== AI Quiz Terminal ===\n")
    take_quiz()
    print("Thanks for playing! Goodbye!\n")
