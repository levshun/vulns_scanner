from flask import Flask, render_template, request, flash
from start_model import run  # import your run function

app = Flask(__name__)
# app.secret_key = 'super-secret-key'

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    input_text = ''
    if request.method == 'POST':
        
        input_text = request.form.get('text', '')
        if not input_text.strip():
            flash('Please enter a vulnerability description')
        else:
            try:
                # Call the run function with user input
                result = run(input_text)
            except Exception as e:
                flash(f'Error processing text: {str(e)}')
    
    return render_template('index.html', result=result, input_text=input_text)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
