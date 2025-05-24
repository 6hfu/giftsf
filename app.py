from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from simple_salesforce import Salesforce
import os
from datetime import datetime, date, timedelta
import requests
from functools import wraps
from flask import render_template, session
from flask import Flask, render_template, session, redirect, url_for
from datetime import datetime
import re
from dotenv import load_dotenv
import os
from flask import Flask
from flask_wtf import CSRFProtect

load_dotenv()  # .envファイルの内容を読み込む

app = Flask(__name__)
app.secret_key = "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d"

# CSRFを有効化
csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # HTTPSのみ
    SESSION_COOKIE_SAMESITE='Lax'
)


field76_map = {
    "AU光_007": "a05IU00001CHHNJYA5",
    "AU光_008": "a05IU00001CHHMwYAP",
    "NURO光_002": "a05IU00001CHHNiYAP",
    "So-net光_002": "a05IU00001CHHNDYA5",
}

BASIC_AUTH_PASSWORD = "gift2025"  # パスワードは変わらず利用

# Salesforce接続
sf = Salesforce(
    username=os.getenv("SF_USERNAME"),
    password=os.getenv("SF_PASSWORD"),
    security_token=os.getenv("SF_SECURITY_TOKEN"),
    domain="login"
)


def check_auth(username, password):
    if password != BASIC_AUTH_PASSWORD:
        return False
    query = "SELECT Field11__c FROM CustomObject10__c WHERE Field11__c != null"
    res = sf.query(query)
    valid_usernames = [record['Field11__c'] for record in res['records']]
    return username in valid_usernames

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("ログインが必要です")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# 郵便番号から住所取得
def get_address_from_postalcode(postal_code):
    if not postal_code:
        return ""
    postal_code = postal_code.replace("-", "").strip()
    if len(postal_code) != 7 or not postal_code.isdigit():
        return ""
    url = f"https://zipcloud.ibsnet.co.jp/api/search?zipcode={postal_code}"
    try:
        res = requests.get(url)
        res.raise_for_status()
        data = res.json()
        if data['results']:
            result = data['results'][0]
            address = result['address1'] + result['address2'] + result['address3']
            return address
        else:
            return ""
    except Exception:
        return ""

def get_field_descriptions():
    desc = sf.restful('sobjects/Account/describe')
    import_fields = [
        'Field206__c', 'Name', 'Field78__c', 'Field56__c', 'Field22__c',
        'Field23__c', 'Field24__c', 'Field25__c', 'Field76__c', 'Field8__c',
        'Field207__c', 'ShippingPostalCode', 'Field6__c', 'Field9__c', 'Field40__c',
        'X2__c', 'Field27__c', 'Field28__c', 'Field30__c', 'Field31__c',
        'Field41__c', 'Field39__c', 'Field35__c', 'Field36__c', 'Field37__c',
        'Field38__c', 'Field12__c', 'Field14__c', 'KDDI__c', 'KDDI1__c',
        'NTT__c', 'NTT1__c', 'Field184__c'
    ]
    field_defs = {}
    for f in desc['fields']:
        if f['name'] in import_fields:
            field_defs[f['name']] = {
                'label': f['label'],
                'type': f['type'],
                'picklistValues': [p['value'] for p in f.get('picklistValues', []) if not p.get('inactive', False)],
                'relationshipName': f.get('relationshipName')
            }
    return field_defs




@app.route('/')
@login_required
def index():
    return redirect(url_for('menu_page'))  # '/'に来たら'/menu'にリダイレクト

@app.route('/form')
@login_required
def form():
    fields = get_field_descriptions()
    today = date.today().isoformat()
    postal_code = request.args.get('ShippingPostalCode', '')
    postal_address = get_address_from_postalcode(postal_code)
    return render_template('form.html',
                           fields=fields,
                           import_fields=list(fields.keys()),
                           field76_map=field76_map,
                           basic_auth_user_id=session.get('username', ''),
                           today=today,
                           postal_code=postal_code,
                           postal_address=postal_address)

@app.route('/submit', methods=['POST'])
@login_required
def submit():
    import_fields = [
        'Field206__c', 'Name', 'Field78__c', 'Field56__c', 'Field22__c',
        'Field23__c', 'Field24__c', 'Field25__c', 'Field76__c', 'Field8__c',
        'Field207__c', 'ShippingPostalCode', 'Field6__c', 'Field9__c', 'Field40__c',
        'X2__c', 'Field27__c', 'Field28__c', 'Field30__c', 'Field31__c',
        'Field41__c', 'Field39__c', 'Field35__c', 'Field36__c', 'Field37__c',
        'Field38__c', 'Field12__c', 'Field14__c', 'KDDI__c', 'KDDI1__c',
        'NTT__c', 'NTT1__c', 'Field184__c'
    ]
    form_data = {field: request.form.get(field) for field in import_fields}
    form_data['Field207__c'] = session.get('username', None)

    for date_field in ['Field24__c', 'Field41__c']:
        if form_data.get(date_field):
            try:
                dt = datetime.strptime(form_data[date_field], "%Y-%m-%d")
                form_data[date_field] = dt.strftime("%Y-%m-%d")
            except Exception:
                form_data[date_field] = None

    input_time_str = form_data.get("Field25__c")
    if input_time_str:
        try:
            input_time = datetime.strptime(input_time_str, "%H:%M")
            jst_time = (input_time + timedelta(hours=9)).time()
            form_data["Field25__c"] = jst_time.strftime("%H:%M:%S")
        except Exception:
            form_data["Field25__c"] = None

    if form_data.get('Field76__c') in field76_map:
        form_data['Field76__c'] = field76_map[form_data['Field76__c']]
    else:
        form_data['Field76__c'] = None

    try:
        result = sf.Account.create(form_data)
        message = f"レコード作成成功。ID: {result['id']}"
    except Exception as e:
        message = f"エラー発生: {str(e)}"

    return render_template('result.html', message=message)

@app.route('/search/customobject10')
@login_required
def search_customobject10():
    q = request.args.get('q', '')
    soql = f"SELECT Id, Name FROM CustomObject10__c WHERE Name LIKE '%{q}%' ORDER BY Name LIMIT 20"
    res = sf.query(soql)
    results = [{'id': r['Id'], 'text': r['Name']} for r in res['records']]
    return jsonify({'results': results})

@app.route('/search/customobject1')
@login_required
def search_customobject1():
    q = request.args.get('q', '')
    soql = f"SELECT Id, Name FROM CustomObject1__c WHERE Name LIKE '%{q}%' ORDER BY Name LIMIT 20"
    res = sf.query(soql)
    results = [{'id': r['Id'], 'text': r['Name']} for r in res['records']]
    return jsonify({'results': results})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if check_auth(username, password):
            session['username'] = username
            flash('ログイン成功しました')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('menu_page'))
        else:
            flash('ユーザー名またはパスワードが間違っています')
            return render_template('login.html')
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('ログアウトしました')
    return redirect(url_for('login'))


@app.route('/records')
@login_required
def records():
    login_id = session.get('username')
    if not login_id:
        flash("ログインIDがセッションにありません")
        return redirect(url_for('login'))

    try:
        soql = """
            SELECT Name, timetorihiki__c, Field101__c, Field97__c, CLOK__c, Field118__c, Field171__c, Field172__c
            FROM Account
            WHERE Field207__c = '{}'
            ORDER BY CreatedDate DESC
            LIMIT 100
        """.format(login_id)

        result = sf.query(soql)
        records = result.get('records', [])

        for record in records:
            # timetorihiki__c を YYYY/MM/DD に変換
            dt_str = record.get('timetorihiki__c')
            if dt_str:
                try:
                    dt = datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S.%f%z')
                    record['timetorihiki__c_formatted'] = dt.strftime('%Y/%m/%d')
                except Exception:
                    record['timetorihiki__c_formatted'] = dt_str
            else:
                record['timetorihiki__c_formatted'] = ''

            # Field97__c を YYYY/MM/DD HH:MM 形式に変換（日時両対応）
            dt97_str = record.get('Field97__c')
            if dt97_str:
                try:
                    dt97_fixed = re.sub(r'Z$', '+0000', dt97_str)
                    dt97 = datetime.strptime(dt97_fixed, '%Y-%m-%dT%H:%M:%S.%f%z')
                    record['Field97__c_formatted'] = dt97.strftime('%Y/%m/%d %H:%M')
                except Exception:
                    record['Field97__c_formatted'] = dt97_str
            else:
                record['Field97__c_formatted'] = ''

        return render_template('records.html', records=records)
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"レコード取得中にエラーが発生しました: {str(e)}")
        return redirect(url_for('menu_page'))



@app.route('/menu_page')
@login_required
def menu_page():
    login_id = session.get('username')
    if not login_id:
        flash("ログインIDがセッションにありません")
        return redirect(url_for('login'))
    try:
        soql = f"SELECT Name, Field13__c FROM CustomObject10__c WHERE Field11__c = '{login_id}' LIMIT 1"
        result = sf.query(soql)
        if result['totalSize'] == 0:
            flash("ユーザー情報が見つかりませんでした")
            return redirect(url_for('logout'))
        record = result['records'][0]
        display_name = record.get('Name', '')
        department = record.get('Field13__c', '')
        return render_template('menu.html', username=display_name, department=department)
    except Exception as e:
        flash(f"Salesforceの取得中にエラーが発生しました: {str(e)}")
        return redirect(url_for('logout'))





if __name__ == '__main__':
    app.run(debug=True)
