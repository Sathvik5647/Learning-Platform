from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import random
import os
from datetime import datetime

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///learning_platform.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Association table for many-to-many relationship between users and badges
user_badges = db.Table('user_badges',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('badge_id', db.Integer, db.ForeignKey('badge.id'), primary_key=True)
)

# Association table for user interests
user_interests = db.Table('user_interests',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('topic_id', db.Integer, db.ForeignKey('topic.id'), primary_key=True)
)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    score = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    badges = db.relationship('Badge', secondary=user_badges, lazy='subquery',
                           backref=db.backref('users', lazy=True))
    interests = db.relationship('Topic', secondary=user_interests, lazy='subquery',
                              backref=db.backref('interested_users', lazy=True))
    quiz_history = db.relationship('QuizHistory', backref='user', lazy=True, cascade='all, delete-orphan')

    def has_badge(self, badge_name):
        return any(badge.name == badge_name for badge in self.badges)
    
    def add_badge(self, badge_name):
        if not self.has_badge(badge_name):
            badge = Badge.query.filter_by(name=badge_name).first()
            if badge:
                self.badges.append(badge)
                return True
        return False

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    description = db.Column(db.String(200))
    questions = db.relationship('Question', backref='topic_obj', lazy=True)

class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    points_required = db.Column(db.Integer, default=0)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    answer = db.Column(db.String(100), nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=False)
    difficulty = db.Column(db.Integer, nullable=False)  # 1: Easy, 2: Medium, 3: Hard
    options = db.Column(db.Text, nullable=True)  # JSON string for options
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    quiz_history = db.relationship('QuizHistory', backref='question', lazy=True)

class QuizHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_answer = db.Column(db.String(100))
    is_correct = db.Column(db.Boolean)
    answered_at = db.Column(db.DateTime, default=datetime.utcnow)
    points_earned = db.Column(db.Integer, default=0)

class QuizSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(100), nullable=False)
    answered_questions = db.Column(db.Text, default='')  # JSON string of question IDs
    question_limit = db.Column(db.Integer, default=5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

# User Loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility Functions
def get_user_difficulty(user):
    """Calculate appropriate difficulty based on user score"""
    if user.score < 50:
        return 1
    elif user.score < 150:
        return 2
    else:
        return 3

def check_and_award_badges(user):
    """Check if user qualifies for new badges"""
    badges_awarded = []
    
    if user.score >= 50 and not user.has_badge('Novice'):
        if user.add_badge('Novice'):
            badges_awarded.append('Novice')
    
    if user.score >= 150 and not user.has_badge('Intermediate'):
        if user.add_badge('Intermediate'):
            badges_awarded.append('Intermediate')
    
    if user.score >= 300 and not user.has_badge('Expert'):
        if user.add_badge('Expert'):
            badges_awarded.append('Expert')
    
    return badges_awarded

def validate_input(data, required_fields):
    """Validate required form fields"""
    errors = []
    for field in required_fields:
        if not data.get(field) or not data.get(field).strip():
            errors.append(f'{field.replace("_", " ").title()} is required')
    return errors

# Initialize database with sample data
def seed_data():
    # Create topics
    if Topic.query.count() == 0:
        topics = [
            Topic(name='Python', description='Python programming language'),
            Topic(name='Math', description='Mathematics and calculations'),
            Topic(name='Web Development', description='HTML, CSS, JavaScript'),
            Topic(name='Data Structures', description='Data structures and algorithms'),
            Topic(name='Databases', description='Database concepts and SQL'),
            Topic(name='OOP', description='Object-Oriented Programming'),
            Topic(name='AI', description='Artificial Intelligence and Machine Learning'),
        ]
        db.session.bulk_save_objects(topics)
        db.session.commit()

    # Create badges
    if Badge.query.count() == 0:
        badges = [
            Badge(name='Novice', description='Score 50 points', points_required=50),
            Badge(name='Intermediate', description='Score 150 points', points_required=150),
            Badge(name='Expe rt', description='Score 300 points', points_required=300),
        ]
        db.session.bulk_save_objects(badges)
        db.session.commit()

    # Create questions
    if Question.query.count() == 0:
        python_topic = Topic.query.filter_by(name='Python').first()
        math_topic = Topic.query.filter_by(name='Math').first()
        web_topic = Topic.query.filter_by(name='Web Development').first()
        ds_topic = Topic.query.filter_by(name='Data Structures').first()
        db_topic = Topic.query.filter_by(name='Databases').first()
        oop_topic = Topic.query.filter_by(name='OOP').first()
        ai_topic = Topic.query.filter_by(name='AI').first()

        questions = [
            # Python
            Question(text="What is Python?", answer="A programming language", 
                    options="A snake,A programming language,An operating system,A database", 
                    topic_id=python_topic.id, difficulty=1),
            Question(text="What is a list in Python?", answer="A mutable sequence", 
                    options="An immutable tuple,A function,A mutable sequence,A dictionary", 
                    topic_id=python_topic.id, difficulty=2),
            Question(text="What is a decorator in Python?", answer="A function that modifies another function", 
                    options="A loop,A module,A function that modifies another function,An error handler", 
                    topic_id=python_topic.id, difficulty=3),

            # Math
            Question(text="What is 2+2?", answer="4", options="3,4,5,6", 
                    topic_id=math_topic.id, difficulty=1),
            Question(text="What is the square root of 16?", answer="4", options="2,4,6,8", 
                    topic_id=math_topic.id, difficulty=2),

            # Web Development
            Question(text="What does HTML stand for?", answer="HyperText Markup Language", 
                    options="Hyper Transfer Markup Language,HyperText Markup Language,Hyper Tool Markup Language,Home Tool Markup Language", 
                    topic_id=web_topic.id, difficulty=1),
            Question(text="Which tag is used for creating links in HTML?", answer="a", 
                    options="div,span,a,link", topic_id=web_topic.id, difficulty=1),
            Question(text="Which language is used to style web pages?", answer="CSS", 
                    options="HTML,CSS,JavaScript,SQL", topic_id=web_topic.id, difficulty=1),

            # Data Structures
            Question(text="Which data structure uses LIFO?", answer="Stack", 
                    options="Queue,Stack,Array,Graph", topic_id=ds_topic.id, difficulty=1),
            Question(text="Which data structure uses FIFO?", answer="Queue", 
                    options="Queue,Stack,Array,Tree", topic_id=ds_topic.id, difficulty=1),
            Question(text="Which structure is used to represent hierarchical data?", answer="Tree", 
                    options="Tree,Stack,Array,Queue", topic_id=ds_topic.id, difficulty=2),

            # Databases
            Question(text="What does SQL stand for?", answer="Structured Query Language", 
                    options="Strong Question Language,Structured Query Language,Simple Query Language,Server Query Language", 
                    topic_id=db_topic.id, difficulty=1),
            Question(text="Which command is used to retrieve data?", answer="SELECT", 
                    options="INSERT,SELECT,UPDATE,DELETE", topic_id=db_topic.id, difficulty=1),

            # OOP
            Question(text="What is inheritance in OOP?", answer="Acquiring properties of a parent class", 
                    options="Code duplication,Method overriding,Acquiring properties of a parent class,Encapsulation", 
                    topic_id=oop_topic.id, difficulty=2),
            Question(text="Which concept hides internal details?", answer="Abstraction", 
                    options="Abstraction,Inheritance,Polymorphism,Encapsulation", 
                    topic_id=oop_topic.id, difficulty=1),

            # AI
            Question(text="What does AI stand for?", answer="Artificial Intelligence", 
                    options="Automated Intelligence,Artificial Integration,Artificial Intelligence,Automated Interface", 
                    topic_id=ai_topic.id, difficulty=1),
            Question(text="Which is a type of AI?", answer="Machine Learning", 
                    options="Machine Learning,Database Design,Web Hosting,Data Entry", 
                    topic_id=ai_topic.id, difficulty=1),
        ]

        db.session.bulk_save_objects(questions)
        db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Validate input
        required_fields = ['username', 'password', 'confirm_password']
        errors = validate_input(request.form, required_fields)
        
        if errors:
            for error in errors:
                flash(error)
            return redirect(url_for('signup'))

        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        selected_interests = request.form.getlist('interests')

        # Additional validation
        if len(username) < 3:
            flash('Username must be at least 3 characters long!')
            return redirect(url_for('signup'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long!')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('signup'))

        # Create user
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        
        # Add interests
        for interest_name in selected_interests:
            topic = Topic.query.filter_by(name=interest_name).first()
            if topic:
                user.interests.append(topic)

        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))

    topics = Topic.query.all()
    return render_template('signup.html', topics=topics)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        errors = validate_input(request.form, ['username', 'password'])
        
        if errors:
            for error in errors:
                flash(error)
            return render_template('login.html')

        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        
        flash('Invalid username or password!')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Clean up any active quiz sessions
    QuizSession.query.filter_by(user_id=current_user.id, is_active=True).update({'is_active': False})
    db.session.commit()
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    recent_history = QuizHistory.query.filter_by(user_id=user.id)\
                                    .order_by(QuizHistory.answered_at.desc())\
                                    .limit(5).all()
    
    # Calculate statistics
    total_questions = QuizHistory.query.filter_by(user_id=user.id).count()
    correct_answers = QuizHistory.query.filter_by(user_id=user.id, is_correct=True).count()
    accuracy = round((correct_answers / total_questions * 100), 1) if total_questions > 0 else 0
    
    return render_template('dashboard.html', 
                         user=user, 
                         recent_history=recent_history,
                         total_questions=total_questions,
                         accuracy=accuracy)

@app.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    import json
    
    user = current_user
    session_id = session.get('quiz_session_id')
    
    # Get or create quiz session
    quiz_session = None
    if session_id:
        quiz_session = QuizSession.query.filter_by(
            user_id=user.id, 
            session_id=session_id, 
            is_active=True
        ).first()
    
    if not quiz_session:
        session_id = f"{user.id}_{datetime.utcnow().timestamp()}"
        quiz_session = QuizSession(
            user_id=user.id,
            session_id=session_id,
            answered_questions='[]',
            question_limit=5
        )
        db.session.add(quiz_session)
        db.session.commit()
        session['quiz_session_id'] = session_id

    answered_questions = json.loads(quiz_session.answered_questions) if quiz_session.answered_questions else []
    
    # Check if quiz is complete
    if len(answered_questions) >= quiz_session.question_limit:
        flash(f'Quiz completed! You answered {len(answered_questions)} questions.')
        quiz_session.is_active = False
        db.session.commit()
        session.pop('quiz_session_id', None)
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        question_id = int(request.form['question_id'])
        user_answer = request.form['answer'].strip()
        question = Question.query.get(question_id)

        if not question:
            flash('Question not found!')
            return redirect(url_for('quiz'))

        is_correct = user_answer.lower() == question.answer.lower()
        points_earned = 0
        
        if is_correct:
            points_earned = question.difficulty * 10
            user.score += points_earned
            flash(f'Correct! +{points_earned} points')
        else:
            flash(f'Incorrect! The correct answer was: {question.answer}')

        # Save to quiz history
        history = QuizHistory(
            user_id=user.id,
            question_id=question.id,
            user_answer=user_answer,
            is_correct=is_correct,
            points_earned=points_earned
        )
        db.session.add(history)

        # Update quiz session
        answered_questions.append(question_id)
        quiz_session.answered_questions = json.dumps(answered_questions)
        
        # Check for new badges
        new_badges = check_and_award_badges(user)
        for badge in new_badges:
            flash(f'Congratulations! You earned the "{badge}" badge!')

        db.session.commit()
        return redirect(url_for('quiz'))

    # Get next question
    user_interests = [topic.id for topic in user.interests] if user.interests else [1]  # Default to first topic
    difficulty = get_user_difficulty(user)

    available_questions = Question.query.filter(
        Question.topic_id.in_(user_interests),
        Question.difficulty <= difficulty,
        Question.is_active == True,
        ~Question.id.in_(answered_questions)
    ).all()

    if not available_questions:
        flash('No more questions available! Try expanding your interests.')
        quiz_session.is_active = False
        db.session.commit()
        session.pop('quiz_session_id', None)
        return redirect(url_for('dashboard'))

    question = random.choice(available_questions)
    progress = {
        'current': len(answered_questions) + 1,
        'total': quiz_session.question_limit
    }
    
    return render_template('quiz.html', question=question, progress=progress)

@app.route('/quiz_exit')
@login_required
def quiz_exit():
    session_id = session.get('quiz_session_id')
    if session_id:
        QuizSession.query.filter_by(
            user_id=current_user.id, 
            session_id=session_id
        ).update({'is_active': False})
        db.session.commit()
        session.pop('quiz_session_id', None)
    
    flash('Quiz session ended.')
    return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        selected_interests = request.form.getlist('interests')
        user = current_user
        
        # Clear current interests
        user.interests.clear()
        
        # Add new interests
        for interest_name in selected_interests:
            topic = Topic.query.filter_by(name=interest_name).first()
            if topic:
                user.interests.append(topic)
        
        db.session.commit()
        flash('Interests updated successfully!')
        return redirect(url_for('profile'))
    
    topics = Topic.query.all()
    return render_template('profile.html', topics=topics)

@app.route('/leaderboard')
def leaderboard():
    top_users = User.query.order_by(User.score.desc()).limit(10).all()
    return render_template('leaderboard.html', top_users=top_users)

# Admin Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    
    stats = {
        'total_users': User.query.count(),
        'total_questions': Question.query.count(),
        'total_quiz_attempts': QuizHistory.query.count(),
        'active_topics': Topic.query.count()
    }
    
    return render_template('admin_dashboard.html', stats=stats)

@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if not current_user.is_admin:
        flash('Access denied!')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        errors = validate_input(request.form, ['text', 'answer', 'topic_id', 'difficulty'])
        
        if errors:
            for error in errors:
                flash(error)
            return redirect(url_for('add_question'))

        text = request.form['text'].strip()
        answer = request.form['answer'].strip()
        options = request.form.get('options', '').strip()
        topic_id = int(request.form['topic_id'])
        difficulty = int(request.form['difficulty'])

        if difficulty not in [1, 2, 3]:
            flash('Difficulty must be 1, 2, or 3!')
            return redirect(url_for('add_question'))

        question = Question(
            text=text,
            answer=answer,
            options=options,
            topic_id=topic_id,
            difficulty=difficulty
        )
        db.session.add(question)
        db.session.commit()
        flash('Question added successfully!')
        return redirect(url_for('add_question'))

    topics = Topic.query.all()
    return render_template('add_question.html', topics=topics)

@app.route('/admin/manage_users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/toggle_admin/<int:user_id>')
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = "granted" if user.is_admin else "revoked"
    flash(f'Admin access {status} for {user.username}')
    return redirect(url_for('manage_users'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_data()
        
        # Create default admin user if it doesn't exist
        admin = User.query.filter_by(username='Sathvik').first()
        if not admin:
            admin = User(
                username='Sathvik',
                password_hash=generate_password_hash('sathvik123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: username='Sathvik', password='sathvik123'")
    
    app.run(debug=True)