#encoding: utf-8
from flask import Flask, render_template, url_for, request, redirect
from flask_wtf import FlaskForm
from wtforms import validators, fields, widgets
from flask_bootstrap import Bootstrap
# from flask.ext.bootstrap import Bootstrap
from wvs import wvs

app = Flask(__name__)
app.config.from_object('app.config.Config')
bootstrap = Bootstrap(app)
wvs = wvs()

# class MyForm(FlaskForm):
#     Username = fields.StringField(
#         label='用户名',
#         validators=[
#             validators.DataRequired(message='用户名不能为空'),
#             validators.length(min=6, max=11, message='用户名长度必须大于%(min)d且小于%(max)d')
#         ],
#         widget=widgets.TextInput(),
#         render_kw={
#             'class': 'form-control',
#             'placeholder': '请输入用户名',
#             'required': '',
#             'autofocus': ''
#         }
#     )
#     Password = fields.PasswordField(
#         label='密码',
#         validators=[
#             validators.DataRequired(message='密码不能为空'),
#             validators.length(min=6, message='密码必须大于%(min)d位')
#         ],
#         widget=widgets.PasswordInput(),
#         render_kw={
#             'class': 'form-control',
#             'placeholder': '请输入密码',
#             'required': '',
#             'autofocus': ''
#         }
#     )
#
#
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'GET':
#         form = MyForm()
#     if request.method == 'POST':
#         form = MyForm(request.form)
#         if form.validate_on_submit():
#             return redirect('http://www.baidu.com')
#         else:
#             print(form.errors)
#     return render_template('admin/login.html', form = form)


@app.route('/',methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/Home')
def home():
    info = wvs.scan_status()
    return render_template('home.html',info=info)

@app.route('/',methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if username == 'sangfor' and password=='sangfor':
        info="login success!"  #调用wvs整体安全状态返回数据
        return redirect(url_for('.home'))
    else:
        error='Bad UserName Or Password!'
        return render_template('index.html',error=error)

@app.route('/Target',methods=['GET'])
def target_form():
    targets_info = wvs.getTargets()


    return render_template('target.html',targets_info=targets_info)


@app.route('/Target',methods=['POST'])
def target():
    urls = str(request.form['urls'])
    description = request.form['description']
    profile_id = request.form['profile_id']
    urls = urls.split(',')
    for url in urls:
        print url
        print description
        print(profile_id)
        target_id = wvs.startscan(url,description,profile_id=profile_id)
        if(target_id):
            return render_template('target_add.html',url=url)
        else:
            return redirect(url_for('.target'))




@app.route('/target_detail/<target_id>',methods=['GET','POST'])
def target_detail(target_id):
    target = wvs.getTargetInformation(target_id)
    print target
    return render_template('target_detail.html',target=target)

@app.route('/targets/<target_id>',methods=['DELETE'])
def delete_target(target_id):
    result = ''
    if(wvs.delete_target(target_id)):
        result = "删除成功"
    else:
        result = "删除失败"
    return result






@app.route('/Scan',methods=['GET'])
def scan_form():
    # wvs.getscan()  获取到所有的扫描状态
    scan_info=wvs.getscan()
    print scan_info
    return render_template('scan.html',scan_info=scan_info)

@app.route('/scans/<scan_id>',methods=['DELETE'])
def delete_scan(scan_id):
    result = ''
    if (wvs.delete_scan(scan_id)):
        result = "删除成功"
    else:
        result = "删除失败"
    return result


@app.route('/scan_list/<scan_id>&<scan_session_id>',methods=['GET'])
def scan_list(scan_id,scan_session_id):
    vulns_info=wvs.getScanDetail(scan_id,scan_session_id)
    vulns = vulns_info['vulnerabilities']
    url = scan_id+"&"+scan_session_id
    return render_template('scan_vuln_list.html',vulns=vulns,url=url)

@app.route('/scan_detail/<scan_id>&<scan_session_id>',methods=['GET'])
def scan_detail(scan_id,scan_session_id):
    #得到某次扫描整体扫描情况
    scan=wvs.getScanStatistics(scan_id,scan_session_id)
    print scan
    target_id = scan['scanning_app']['wvs']['main']['messages'][0]['target_info']['target_id']
    target_info = scan['scanning_app']['wvs']['hosts'][target_id]['target_info']
    print target_info
    hosts = scan['scanning_app']['wvs']['hosts'][target_id]['external_hosts']
    url = scan_id+"&"+scan_session_id
    return render_template('scan_detail.html',scan=scan,target_info=target_info,hosts=hosts,url=url)


@app.route('/Vuln',methods=['GET'])
def vuln_form():
    vulns = wvs.getvulnerabilities()
    return render_template('vuln.html',vulns=vulns)


@app.route('/vuln_detail/<vuln_id>',methods=['GET'])
def vuln_detail(vuln_id):
    print vuln_id
    vuln=wvs.getvulnerabilitiesinfo(vuln_id)
    print vuln
    vuln['request'] = vuln['request'].replace('\r\n', '</br>')
    return render_template('vuln_detail.html',vuln=vuln)

@app.route('/scan_vuln_detail/<url>&<vuln_id>',methods=['GET'])
def scan_vuln_detail(url,vuln_id):
    print vuln_id
    scan_id = url.split('&')[0]
    scan_session_id = url.split('&')[1]
    vuln=wvs.getvulnerabilitiesinfo1(scan_id,scan_session_id,vuln_id)
    vuln['request'] = vuln['request'].replace('\r\n','</br>')
    return render_template('vuln_detail.html',vuln=vuln)


@app.route('/vulnerabilities/<vuln_id>',methods=['PUT'])
def recheckvuln(vuln_id):
    result = ""
    print vuln_id


    print wvs.scan_check(vuln_id)

    return result



@app.route('/Report',methods=['GET'])
def report_form():
    report_info = wvs.getAllReports()
    print report_info
    return render_template('report.html',report_info=report_info)

@app.route('/report/<scan_id>')
def generate(scan_id):
    result = ""
    if(wvs.getreports(scan_id)):
        result = "生成报告成功"
    else:
        result = "生成报告失败"

    return result

@app.route('/About')
def about():
    info='Welcome to SSECTools'
    return render_template('about.html',info=info)



@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'),404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'),500

