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
import pandas as pd


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
    "NURO光_002（OIM）": "a05IU00001CHHNiYAP",
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

    try:
        # Field11__c（ログインID）で検索し、Field23__c の有無を確認
        query = f"""
            SELECT Field11__c, Field23__c
            FROM CustomObject10__c
            WHERE Field11__c = '{username}'
            LIMIT 1
        """
        res = sf.query(query)

        if res['totalSize'] == 0:
            # ユーザーが存在しない
            return False

        record = res['records'][0]
        # Field23__c に値が入っていたらログイン拒否
        if record.get('Field23__c'):
            return False

        # Field11__c が存在し、Field23__c が空ならログインOK
        return True

    except Exception as e:
        print(f"Salesforce認証中にエラー発生: {e}")
        return False


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
        'Field206__c', 'Name', 'Field78__c', 'Field56__c', 'Field228__c', 'Field22__c',
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
        'Field206__c', 'Name', 'Field78__c', 'Field56__c', 'Field228__c', 'Field22__c',
        'Field23__c', 'Field24__c', 'Field25__c', 'Field76__c', 'Field8__c',
        'Field207__c', 'ShippingPostalCode', 'ShippingState', 'ShippingCity', 'ShippingStreet',
        'Field6__c', 'Field9__c', 'Field40__c', 'X2__c', 'Field27__c', 'Field28__c',
        'Field30__c', 'Field31__c', 'Field41__c', 'Field39__c', 'Field35__c', 'Field36__c',
        'Field37__c', 'Field38__c', 'Field12__c', 'Field14__c', 'KDDI__c', 'KDDI1__c',
        'NTT__c', 'NTT1__c', 'NTTX__c', 'Field184__c', 'Field229__c','Field271__c','Field270__c'
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
            SELECT 
                Id, 
                Name, 
                Field106__c, 
                timetorihiki__c, 
                Field101__c, 
                Field97__c, 
                CLOK__c, 
                Field118__c, 
                Field171__c, 
                Field172__c
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


@app.route("/admin")
@admin_required
def admin_page():
    try:
        # Salesforceから全取引先案件データを取得
        query = """
            SELECT Id, Name, Field140__c, Field93__r.Field2__c, Field211__c,
                   Field96__r.Field2__c, Field102__r.Field2__c, Field101__c,
                   CLOK__c, atokakuOK__c, Field118__c, Field119__c, maekakuNGi__c,
                   atokakuNGi__c, NGriyu__c, Field1__c, Field78__c, Field76__r.Name,
                   Field22__c, Field43__c, Field6__c, Field56__c, Field12__c,
                   Field14__c, Field13__c, Field15__c, Field23__c, Field34__c,
                   Field63__c, Field262__c, Ltotugo__c, Field266__c,
                   Field79__r.Field1__c
            FROM Account
            ORDER BY Field79__r.Field1__c DESC NULLS LAST
            LIMIT 1000
        """
        result = sf.query_all(query)
        records = result.get("records", [])

        return render_template("admin_page.html",
                               username="管理者",
                               records=records)

    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"管理者ページでエラーが発生しました: {str(e)}")
        return redirect(url_for("menu_page"))


@app.route("/update_records", methods=["POST"])
@admin_required
def update_records():
    try:
        record_id = request.form.get("update_id")
        # 更新対象フィールド（例：ステータス）
        new_status = request.form.get(f"Field101__c_{record_id}")

        if not record_id:
            flash("更新対象のレコードIDが指定されていません。")
            return redirect(url_for("admin_page"))

        update_data = {}
        if new_status is not None:
            update_data["Field101__c"] = new_status

        if update_data:
            sf.Account.update(record_id, update_data)
            flash(f"レコード {record_id} を更新しました。")

        return redirect(url_for("admin_page"))

    except Exception as e:
        flash(f"更新時にエラーが発生しました: {str(e)}")
        return redirect(url_for("admin_page"))

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    today = datetime.now()
    today_str = today.strftime("%Y-%m-%d")
    today_day = today.day  # 例: 10
    target_label = f"{today_day}日稼働時間"

    # --- ラベルからAPI参照名を特定 ---
    field_describe = sf.CustomObject11__c.describe()
    day_field_api = None
    for field in field_describe['fields']:
        if field['label'] == target_label:
            day_field_api = field['name']
            break

    if not day_field_api:
        return f"⚠ {target_label} のフィールドが見つかりません。Salesforceを確認してください。"

    # --- 稼働時間データ ---
    work_query = f"""
        SELECT Name, Field163__c, {day_field_api}
        FROM CustomObject11__c
        WHERE Field163__c = THIS_MONTH
        AND Name LIKE '%獲得者%'
    """
    work_data = sf.query(work_query)["records"]
    df_work = pd.DataFrame(work_data)
    if df_work.empty:
        return "⚠ 稼働データが取得できませんでした。"

    # --- 案件データ（Account） ---
    account_query = """
        SELECT Name, Field79__r.Field1__c, CLOK__c,
               Field211__c, Field140__c, Field161__c
        FROM Account
        WHERE Field79__r.Field1__c != null OR CLOK__c != null
    """
    account_data = sf.query(account_query)["records"]
    df_acc = pd.DataFrame(account_data)

    # --- 日付整形 ---
    df_acc["受注日"] = pd.to_datetime(df_acc["Field79__r.Field1__c"], errors="coerce")
    df_acc["CLOK日"] = pd.to_datetime(df_acc["CLOK__c"], errors="coerce")
    df_acc["所属部署"] = df_acc["Field140__c"]
    df_acc["所属エリア"] = df_acc["Field161__c"]
    df_acc["獲得者"] = df_acc["Field211__c"]

    # --- 今日分フィルタ ---
    df_today = df_acc[
        (df_acc["受注日"].dt.date == today.date()) | 
        (df_acc["CLOK日"].dt.date == today.date())
    ]

    # === 全体・エリア・部署別集計 ===
    def summarize(df):
        orders = df["受注日"].notna().sum()
        cloks = df["CLOK日"].notna().sum()
        rate = round((cloks / orders) * 100, 1) if orders > 0 else 0
        return {"受注数": orders, "CLOK数": cloks, "CLOK率": rate}

    total_summary = summarize(df_today)
    area_summary = df_today.groupby("所属エリア").apply(summarize).to_dict()
    dept_summary = df_today.groupby("所属部署").apply(summarize).to_dict()

    # === 個人別集計 ===
    df_individual = (
        df_today.groupby("獲得者")
        .agg(受注数=("受注日", "count"), CLOK数=("CLOK日", "count"))
        .reset_index()
    )

    # 稼働時間マージ
    df_work.rename(columns={day_field_api: "稼働時間"}, inplace=True)
    df_work["獲得者"] = df_work["Name"].str.replace("様", "").str.strip()
    df_merged = pd.merge(df_individual, df_work, on="獲得者", how="left")

    # 効率と率を計算
    df_merged["受注効率"] = (df_merged["受注数"] / df_merged["稼働時間"]).round(2)
    df_merged["CLOK効率"] = (df_merged["CLOK数"] / df_merged["稼働時間"]).round(2)
    df_merged["CLOK率"] = (
        (df_merged["CLOK数"] / df_merged["受注数"]) * 100
    ).fillna(0).round(1)

    return render_template(
        "admin_dashboard.html",
        total_summary=total_summary,
        area_summary=area_summary,
        dept_summary=dept_summary,
        individuals=df_merged.to_dict(orient="records"),
        today_label=target_label,
    )

@app.route('/api/search_user', methods=['GET'])
@login_required
def search_user():
    keyword = request.args.get('q', '').strip()
    if not keyword:
        return jsonify([])

    try:
        # 名前 or ログインID（Field11__c）で部分一致検索
        soql = f"""
            SELECT Id, Name, Field11__c
            FROM CustomObject10__c
            WHERE Name LIKE '%{keyword}%' OR Field11__c LIKE '%{keyword}%'
            LIMIT 10
        """
        results = sf.query(soql)['records']

        suggestions = [
            {
                "id": rec["Id"],
                "name": rec["Name"],
                "login": rec.get("Field11__c", "")
            }
            for rec in results
        ]
        return jsonify(suggestions)

    except Exception as e:
        print("検索エラー:", e)
        return jsonify([])


if __name__ == '__main__':
    app.run(debug=True)


from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))

@app.route('/edit_record/<record_id>', methods=['GET'])
def edit_record(record_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Salesforceから該当レコード取得
    query = f"SELECT Id, Name, Field24__c, Field25__c, Field101__c, CLOK__c FROM Account WHERE Id = '{record_id}'"
    result = sf.query(query)

    if not result['records']:
        flash('該当する案件が見つかりません。', 'danger')
        return redirect(url_for('records'))

    record = result['records'][0]

    # CLOK日がある案件は編集不可
    if record.get('CLOK__c'):
        flash('この案件はCLOK日が入力されているため編集できません。', 'warning')
        return redirect(url_for('records'))

    # ▼ JSTの現在日時（デフォルト用）
    now_jst = datetime.now(JST)
    today_jst = now_jst.strftime("%Y-%m-%d")
    time_jst = now_jst.strftime("%H:%M")

    return render_template(
        'edit_record.html',
        record=record,
        today_jst=today_jst,
        time_jst=time_jst
    )





@app.route('/update_record', methods=['POST'])
def update_record():
    if 'username' not in session:
        return redirect(url_for('login'))

    record_id = request.form.get('record_id')
    field24 = request.form.get('Field24__c') or None
    field25 = request.form.get('Field25__c') or None
    field101 = request.form.get('Field101__c') or None

    # CLOK日が入っていたら編集禁止
    check = sf.query(f"SELECT CLOK__c FROM Account WHERE Id = '{record_id}'")
    if check['records'] and check['records'][0].get('CLOK__c'):
        flash('この案件は既にCLOK日が入力されているため変更できません。', 'danger')
        return redirect(url_for('records'))

    try:
        update_data = {}

        # 日付そのまま
        if field24:
            update_data['Field24__c'] = field24

        # ★ 時刻は +9時間して UTC として Salesforce に送る
        if field25:
            # 文字列 → datetime
            t = datetime.strptime(field25, "%H:%M")

            # 日付は今日で扱う（時間だけ使うため日付は捨てる）
            dt_jst = datetime(2024, 1, 1, t.hour, t.minute)

            # UTC に変換（JST → UTC -9時間）
            dt_utc = dt_jst - timedelta(hours=9)

            # SalesforceのTime型フォーマット（HH:MM:SS）
            update_data['Field25__c'] = dt_utc.strftime("%H:%M:%S")

        # 前確ステータス
        if field101 == '前確待ち':
            update_data['Field101__c'] = field101

        if update_data:
            sf.Account.update(record_id, update_data)
            flash('案件を更新しました。', 'success')
        else:
            flash('変更項目がありません。', 'info')

    except Exception as e:
        flash(f'更新エラー: {e}', 'danger')

    return redirect(url_for('records'))

