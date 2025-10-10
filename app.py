from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from simple_salesforce import Salesforce
from datetime import datetime, timedelta, timezone
import requests
from functools import wraps
from dotenv import load_dotenv
import os
from flask_wtf import CSRFProtect
import pytz
import re
from flask import jsonify, render_template
import json


# 環境変数読み込み
load_dotenv()

# Flask設定
app = Flask(__name__)
app.secret_key = "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# セッションタイムアウト時間（8時間）
SESSION_TIMEOUT_HOURS = 4
JST = timezone(timedelta(hours=9))  # 日本時間

# Salesforce接続
sf = Salesforce(
    username=os.getenv("SF_USERNAME"),
    password=os.getenv("SF_PASSWORD"),
    security_token=os.getenv("SF_SECURITY_TOKEN"),
    domain="login"
)

field76_map = {
    "So-net光_004（WAF）": "a05TL00000YGL4vYAH",
    "AU光_010（WAF）": "a05TL00000ncTETYA2",
    "NURO光_003（ワンサービス）": "a05TL00000ljIddYAE",
    "good NP_001（ITC）": "a05TL00000mA0r7YAC",
    "AU光_008（Tアシスト）": "a05IU00001CHHMwYAP"
}

BASIC_AUTH_PASSWORD = "gift2025"

# セッション有効期限確認・更新
@app.before_request
def check_session_timeout():
    if 'username' in session:
        last_activity = session.get('last_activity')
        now = datetime.now(JST)
        if last_activity:
            last_activity_dt = datetime.fromisoformat(last_activity)
            if now - last_activity_dt > timedelta(hours=SESSION_TIMEOUT_HOURS):
                session.clear()
                flash("セッションの有効期限が切れました。再ログインしてください。")
                return redirect(url_for('login'))
        # アクティビティ更新
        session['last_activity'] = now.isoformat()

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
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("管理者権限が必要です")
            return redirect(url_for('menu_page'))
        return f(*args, **kwargs)
    return decorated_function


# 郵便番号から住所取得（分割版）
def get_address_from_postalcode(postal_code):
    """
    郵便番号から住所を取得し、都道府県、市区町村、町名・番地に分割して返す
    戻り値: (postal_code, state, city, street)
    """
    if not postal_code:
        return "", "", "", ""
    postal_code = postal_code.replace("-", "").strip()
    if len(postal_code) != 7 or not postal_code.isdigit():
        return postal_code, "", "", ""
    url = f"https://zipcloud.ibsnet.co.jp/api/search?zipcode={postal_code}"
    try:
        res = requests.get(url)
        res.raise_for_status()
        data = res.json()
        if data['results']:
            result = data['results'][0]
            state = result.get('address1', '')
            city = result.get('address2', '')
            street = result.get('address3', '')
            return postal_code, state, city, street
        else:
            return postal_code, "", "", ""
    except Exception:
        return postal_code, "", "", ""

def get_field_descriptions():
    """
    Salesforce Accountオブジェクトのフィールド情報取得
    必要なフィールドのみフィルタリングして返す
    """
    desc = sf.restful('sobjects/Account/describe')
    import_fields = [
        'Field206__c', 'Name', 'Field78__c', 'Field56__c', 'Field22__c',
        'Field23__c', 'Field24__c', 'Field25__c', 'Field76__c', 'Field8__c',
        'Field207__c', 'ShippingPostalCode', 'ShippingState', 'ShippingCity', 'ShippingStreet',
        'Field6__c', 'Field9__c', 'Field40__c', 'X2__c', 'Field27__c', 'Field28__c',
        'Field30__c', 'Field31__c', 'Field41__c', 'Field39__c', 'Field35__c', 'Field36__c',
        'Field37__c', 'Field38__c', 'Field12__c', 'Field14__c', 'KDDI__c', 'KDDI1__c',
        'NTT__c', 'NTT1__c', 'NTTX__c', 'Field184__c', 'Field229__c','Field271__c'
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
    return redirect(url_for('menu_page'))

@app.route('/form')
@login_required
def form():
    login_id = session.get('username')
    if not login_id:
        flash("ログインIDがセッションにありません")
        return redirect(url_for('login'))
    
    try:
        # Salesforceからユーザー名と部署名を取得
        soql = f"SELECT Name, Field13__c FROM CustomObject10__c WHERE Field11__c = '{login_id}' LIMIT 1"
        result = sf.query(soql)
        if result['totalSize'] == 0:
            flash("ユーザー情報が見つかりませんでした")
            return redirect(url_for('logout'))
        record = result['records'][0]
        display_name = record.get('Name', '')
        department = record.get('Field13__c', '')

        # 既存の処理
        fields = get_field_descriptions()
        today = datetime.now(JST).date().isoformat()
        postal_code = request.args.get('ShippingPostalCode', '')

        # 郵便番号から住所を分割して取得
        postal_code, state, city, street = get_address_from_postalcode(postal_code)

        return render_template('form.html',
                               fields=fields,
                               import_fields=list(fields.keys()),
                               field76_map=field76_map,
                               basic_auth_user_id=login_id,
                               today=today,
                               postal_code=postal_code,
                               postal_state=state,
                               postal_city=city,
                               postal_street=street,
                               username=display_name,
                               department=department)
    except Exception as e:
        flash(f"Salesforceの取得中にエラーが発生しました: {str(e)}")
        return redirect(url_for('logout'))


@app.route('/submit', methods=['POST'])
@login_required
def submit():
    import_fields = [
        'Field206__c', 'Name', 'Field78__c', 'Field56__c', 'Field22__c',
        'Field23__c', 'Field24__c', 'Field25__c', 'Field76__c', 'Field8__c',
        'Field207__c', 'ShippingPostalCode', 'ShippingState', 'ShippingCity', 'ShippingStreet',
        'Field6__c', 'Field9__c', 'Field40__c', 'X2__c', 'Field27__c', 'Field28__c',
        'Field30__c', 'Field31__c', 'Field41__c', 'Field39__c', 'Field35__c', 'Field36__c',
        'Field37__c', 'Field38__c', 'Field12__c', 'Field14__c', 'KDDI__c', 'KDDI1__c',
        'NTT__c', 'NTT1__c', 'NTTX__c', 'Field184__c', 'Field229__c','Field271__c'
    ]

    form_data = {field: request.form.get(field) for field in import_fields}
    form_data['Field207__c'] = session.get('username', None)

    # 日付フィールドの整形
    for date_field in ['Field24__c', 'Field41__c']:
        val = form_data.get(date_field)
        if val:
            try:
                dt = datetime.strptime(val, "%Y-%m-%d")
                form_data[date_field] = dt.strftime("%Y-%m-%d")
            except Exception:
                form_data[date_field] = None
        else:
            form_data[date_field] = None

    # 時間フィールドの整形
    input_time_str = form_data.get("Field25__c")
    if input_time_str:
        try:
            input_time = datetime.strptime(input_time_str, "%H:%M")
            jst_time = (input_time + timedelta(hours=9)).time()
            form_data["Field25__c"] = jst_time.strftime("%H:%M:%S")
        except Exception:
            form_data["Field25__c"] = None

    # Field76__c のマッピング
    if form_data.get('Field76__c') in field76_map:
        form_data['Field76__c'] = field76_map[form_data['Field76__c']]
    else:
        form_data['Field76__c'] = None

    # 郵便番号から住所を自動取得して Salesforce に送信（入力されている場合は上書きしない）
    postal_code_input = form_data.get('ShippingPostalCode', '')
    if postal_code_input:
        postal_code, state, city, street = get_address_from_postalcode(postal_code_input)
        form_data['ShippingPostalCode'] = postal_code
        form_data['ShippingState'] = state
        form_data['ShippingCity'] = city
        form_data['ShippingStreet'] = street

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

        # 管理者ログイン（パスワードがadminなら）
        if password == "admin":
            session['username'] = username
            session['is_admin'] = True
            session['last_activity'] = datetime.now(JST).isoformat()
            flash("管理者モードでログインしました")
            return redirect(url_for('admin_page'))

        # 通常ログイン
        if check_auth(username, password):
            session['username'] = username
            session['is_admin'] = False
            session['last_activity'] = datetime.now(JST).isoformat()
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



def format_jst(datetime_str, fmt="%Y/%m/%d %H:%M"):
    try:
        # 'Z'（UTC）を '+0000' に置換
        datetime_str = re.sub(r'Z$', '+0000', datetime_str)
        dt_utc = datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        dt_jst = dt_utc.astimezone(pytz.timezone("Asia/Tokyo"))
        return dt_jst.strftime(fmt)
    except Exception:
        return datetime_str  # エラー時はそのまま返す

@app.route('/records')
@login_required
def records():
    login_id = session.get('username')
    if not login_id:
        flash("ログインIDがセッションにありません")
        return redirect(url_for('login'))

    try:
        soql = f"""
            SELECT Name, Field106__c, timetorihiki__c, Field101__c, Field97__c, CLOK__c, Field118__c, Field171__c, Field172__c
            FROM Account
            WHERE Field207__c = '{login_id}'
            ORDER BY CreatedDate DESC
            LIMIT 500
        """

        result = sf.query(soql)
        records = result.get('records', [])

        for record in records:
            # timetorihiki__c → JST日付形式
            record['timetorihiki__c_formatted'] = format_jst(record.get('timetorihiki__c', ''), fmt="%Y/%m/%d")

            # Field97__c → JST日時形式
            record['Field97__c_formatted'] = format_jst(record.get('Field97__c', ''), fmt="%Y/%m/%d %H:%M")

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

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        login_id = session.get('username')
        if not login_id:
            flash("ログインIDがセッションにありません")
            return redirect(url_for('login'))

        # 現在時刻（JST）
        now = datetime.now(JST)
        start_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start_current = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start_prev = (start_current - timedelta(days=1)).replace(day=1)
        end_prev = start_current - timedelta(seconds=1)

        # Salesforceクエリ
        soql = f"""
            SELECT CreatedDate, CLOK__c, Field118__c, Field101__c
            FROM Account
            WHERE CreatedDate >= {start_prev.strftime('%Y-%m-%dT00:00:00Z')}
            AND Field207__c = '{login_id}'
        """
        res = sf.query_all(soql)
        records = res['records']

        # 指標定義
        stats = {
            'today': {'orders': 0, 'clok': 0, 'entry': 0, 'wait': 0, 'catch': 0},
            'current': {'orders': 0, 'clok': 0, 'entry': 0, 'wait': 0, 'catch': 0},
            'previous': {'orders': 0, 'clok': 0, 'entry': 0, 'wait': 0, 'catch': 0}
        }


        for rec in records:
            created = datetime.fromisoformat(rec['CreatedDate'].replace('Z', '+00:00')).astimezone(JST)

            # 集計対象期間を判定
            if created >= start_today:
                period = 'today'
            elif created >= start_current:
                period = 'current'
            elif created >= start_prev and created <= end_prev:
                period = 'previous'
            else:
                continue  # 集計対象外

            stats[period]['orders'] += 1
            if rec.get('CLOK__c'):
                stats[period]['clok'] += 1
            if rec.get('Field118__c'):
                stats[period]['entry'] += 1
            if rec.get('Field101__c'):
                val = rec['Field101__c']
                # 「後確待ち」か「後確再コール」が含まれる場合
                if '後確待ち' in val or '後確再コール' in val:
                    stats[period]['wait'] += 1
                # 「営業戻し キャッチ」が含まれる場合
                if '営業戻し　キャッチ' in val:
                    stats[period]['catch'] += 1

        return render_template('dashboard.html', dashboard_data=json.dumps(stats, ensure_ascii=False))

    except Exception as e:
        flash(f"ダッシュボードデータ取得失敗: {str(e)}")
        return redirect(url_for('menu_page'))


@app.route('/admin')
@admin_required
def admin_page():
    return render_template('admin.html', username=session.get('username'))





if __name__ == '__main__':
    app.run(debug=True)
