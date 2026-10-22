def start_trace(state, body, diagnostics):
    now=ns(); tr=state['traceId']; root=state['rootSpanId']; agent=state['agentSpanId']; marker=state['publicMarker']; rid=state['runId']
    state['spans']=[span('POST /v2/incidents',2,tr,root,None,now,now+1,{'http.request.method':'POST','http.route':'/v2/incidents','ga5.run.id':rid,'ga5.public.marker':marker}), span('invoke_agent incident-response',1,tr,agent,root,now,now+1,{'ga5.run.id':rid,'ga5.public.marker':marker})]
    state['spans'].append(span('chat incident-plan',3,tr,hx(8),agent,now,now+1,{'ga5.run.id':rid,'ga5.public.marker':marker,'gen_ai.operation.name':'chat','gen_ai.request.model':MODEL}))
    # Logical execute spans and CLIENT spans are recorded from dispatches/receipts.
    for d in diagnostics: add_dispatch(state,d['toolName'],d['arguments'],'diagnostic',d.get('evidence',state['diagnosis']['evidence'][:1]))

def attach_attempt_spans(state, dispatch, receipt, span_id):
    now=ns(); attrs={'ga5.run.id':state['runId'],'ga5.public.marker':state['publicMarker'],'ga5.action.id':dispatch['actionId'],'gen_ai.tool.name':dispatch['toolName'],'gen_ai.tool.call.id':dispatch['callId'],'gen_ai.operation.name':'execute_tool','ga5.phase':dispatch['phase']}
    state['spans'].append(span('execute_tool '+dispatch['toolName'],1,state['traceId'],hx(8),state['agentSpanId'],now,now+1,attrs))
    status=receipt.get('status',0); err=receipt.get('errorType')
    ca={'ga5.run.id':state['runId'],'ga5.public.marker':state['publicMarker'],'ga5.action.id':dispatch['actionId'],'ga5.attempt':dispatch['attempt'],'ga5.receipt.id':receipt.get('receiptId',''),'ga5.receipt.nonce':receipt.get('nonce',''),'http.request.method':'POST','http.request.resend_count':dispatch['attempt']-1,'http.response.status_code':status}
    sc=2 if status==503 or err=='timeout' else 0
    if err: ca['error.type']=err
    elif status==503: ca['error.type']='503'
    state['spans'].append(span('POST tool/'+dispatch['toolName'],3,state['traceId'],span_id,state['agentSpanId'],now,now+1,ca,status=sc))

@app.get('/')
def home(): return jsonify({'service':'Observable Incident Triage','status':'ready','profile':PROFILE})

@app.post('/v2/incidents')
def create_incident():
    body=request.get_json(silent=True)
    if not isinstance(body,dict): return json_error('Invalid JSON object',400)
    if body.get('profile')!=PROFILE: return json_error('Unsupported profile',422)
    required=['runId','agentName','publicMarker','incident','toolCatalog','policy']
    if any(k not in body for k in required) or not valid_id(body.get('runId')) or not isinstance(body.get('incident'),dict) or not isinstance(body.get('toolCatalog'),list) or not isinstance(body.get('policy'),dict): return json_error('Invalid request schema',422)
    inc=body['incident']
    if not all(isinstance(inc.get(k),str) for k in ('incidentId','title','service','transcript')) or not isinstance(inc.get('allowedRootCauses'),list) or not inc['allowedRootCauses']: return json_error('Invalid incident schema',422)
    rid=body['runId']; fp=sha(body); trace,parent,tracestate=parse_trace(request.headers)
    with LOCK:
        c=dbconn(); old=c.execute('SELECT fingerprint,state_json FROM runs WHERE run_id=?',(rid,)).fetchone()
        if old:
            c.close()
            if old['fingerprint']!=fp: return json_error('runId content conflict',409)
            return jsonify(build_response(json.loads(old['state_json'])))
        try: plan=model_plan(body)
        except Exception as e:
            c.close(); return jsonify({'error':'Model planning unavailable','detail':str(e)[:160]}),503
        allowed=set(inc['allowedRootCauses']); ids=set(evidence_ids(inc['transcript']))
        root=plan.get('rootCause'); ev=plan.get('evidence')
        if root not in allowed or not isinstance(ev,list) or not 2<=len(ev)<=4 or len(set(ev))!=len(ev) or not set(ev)<=ids:
            c.close(); return json_error('Planner returned invalid diagnosis/evidence',422)
        catalog=catalog_map(body); diags=plan.get('diagnostics'); effect=plan.get('effect')
        if not isinstance(diags,list) or not 1<=len(diags)<=min(3,int(body['policy'].get('maximumDiagnostics',3))) or not isinstance(effect,dict): c.close(); return json_error('Planner returned invalid action plan',422)
        for d in diags:
            spec=catalog.get(d.get('toolName')) if isinstance(d,dict) else None
            if not spec or not schema_ok(d.get('arguments'),spec.get('inputSchema',{})) or not set(d.get('evidence',ev[:1]))<=set(ev): c.close(); return json_error('Invalid diagnostic dispatch',422)
        es=catalog.get(effect.get('toolName'))
        if not es or effect.get('toolName') not in body['policy'].get('effectTools',[]) or not schema_ok(effect.get('arguments'),es.get('inputSchema',{})): c.close(); return json_error('Invalid effect dispatch',422)
        state={'runId':rid,'status':'waiting','diagnosis':{'rootCause':root,'evidence':ev},'plan':plan,'dispatches':[],'approvals':[],'pending':{},'pendingApproval':None,'actionLog':[],'receiptLog':[],'suppressed':[],'chosenEffect':effect['toolName'],'publicMarker':body['publicMarker'],'traceId':trace,'incomingParent':parent,'tracestate':tracestate,'rootSpanId':hx(8),'agentSpanId':hx(8),'spans':[],'created':time.time(),'bodyFingerprint':fp}
        start_trace(state,body,diags)
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?)',(rid,fp,json.dumps(body,separators=(',',':')),json.dumps(state,separators=(',',':')),time.time())); c.commit(); c.close()
        return jsonify(build_response(state))

@app.post('/v2/incidents/<run_id>/receipts')
def receive_receipts(run_id):
    body=request.get_json(silent=True)
    if not isinstance(body,dict) or not valid_id(body.get('receiptId')): return json_error('Invalid receipt request',400)
    with LOCK:
        c=dbconn(); row=c.execute('SELECT fingerprint,state_json FROM runs WHERE run_id=?',(run_id,)).fetchone()
        if not row: c.close(); return json_error('Unknown runId',404)
        state=json.loads(row['state_json']); rfp=sha(body)
        old=c.execute('SELECT fingerprint,receipt_json FROM receipts WHERE receipt_id=?',(body['receiptId'],)).fetchone()
        if old:
            c.close()
            if old['fingerprint']!=rfp: return json_error('receiptId content conflict',409)
            return jsonify(build_response(state))
        outcomes=body.get('outcomes',[]); approvals=body.get('approvals',[])
        if not isinstance(outcomes,list) or not isinstance(approvals,list): c.close(); return json_error('Invalid receipt arrays',422)
        # Validate every outcome/approval before mutating state.
        for o in outcomes:
            if not isinstance(o,dict) or o.get('callId') not in state['pending'] or o.get('actionId')!=state['pending'][o.get('callId')]['dispatch']['actionId'] or o.get('attempt')!=state['pending'][o.get('callId')]['dispatch']['attempt']:
                c.close(); return json_error('Outcome does not match a pending call',422)
        pa=state.get('pendingApproval')
        for a in approvals:
            if not pa or a.get('approvalId')!=pa['approvalId'] or a.get('decision') not in ('approved','rejected'):
                c.close(); return json_error('Approval does not match pending approval',422)
        c.execute('INSERT INTO receipts VALUES(?,?,?,?)',(body['receiptId'],run_id,rfp,json.dumps(body,separators=(',',':'))))
        state['receiptLog'].append({'receiptId':body['receiptId']})
        for o in outcomes:
            pending=state['pending'].pop(o['callId']); d=pending['dispatch']; state['actionLog'].append(d)
            rec={'receiptId':body['receiptId'],'actionId':o['actionId'],'callId':o['callId'],'attempt':o['attempt'],'status':o.get('status',0),'resultClass':o.get('resultClass',''),'nonce':o.get('nonce','')}
            state['receiptLog'].append(rec); attach_attempt_spans(state,d,rec,pending['spanId'])
            status=o.get('status',0); err=o.get('errorType')
            if status==503 and d['attempt']==1:
                add_dispatch(state,d['toolName'],d['arguments'],d['phase'],d.get('evidence'),d.get('approvalId'),d.get('approvalNonce'),d['actionId'],d['callId'],2)
            elif status==0 and err=='timeout':
                state['suppressed'].append({'toolName':d['toolName'],'reason':'diagnostic_timeout'}); state['status']='failed'
            elif d['phase']=='diagnostic' and status not in (200,201,204):
                state['status']='failed'
        for a in approvals:
            state['receiptLog'].append({'receiptId':body['receiptId'],'approvalId':a['approvalId'],'decision':a['decision'],'nonce':a.get('nonce','')})
            state['pendingApproval']=None; state['approvals']=[]
            if a['decision']=='approved':
                pa0=pa; add_dispatch(state,pa0['toolName'],pa0['arguments'],'effect',state['plan']['effect'].get('evidence',state['diagnosis']['evidence'][:1]),pa0['approvalId'],a.get('nonce'),pa0['actionId'])
            else: state['suppressed'].append({'toolName':pa['toolName'],'reason':'approval_rejected'}); state['status']='failed'
        if not state['pending'] and not state['pendingApproval'] and state['status']=='waiting':
            # All diagnostics succeeded: dispatch effect only after successful diagnostic receipts.
            if any(x.get('phase')=='diagnostic' and x.get('status') not in (200,201,204) for x in state['receiptLog'] if 'phase' in x):
                state['status']='failed'
            elif any(d['phase']=='diagnostic' for d in state['actionLog']) and not any(d['phase']=='effect' for d in state['dispatches']):
                dispatch_effect_or_approval(state,json.loads(c.execute('SELECT request_json FROM runs WHERE run_id=?',(run_id,)).fetchone()[0]))
            elif any(d['phase']=='effect' for d in state['actionLog']): state['status']='completed'; finalize_trace(state)
        persist_state(c,state); c.commit(); c.close()
        return jsonify(build_response(state))

@app.get('/v2/incidents/<run_id>')
def get_incident(run_id):
    c=dbconn(); row=c.execute('SELECT state_json FROM runs WHERE run_id=?',(run_id,)).fetchone(); c.close()
    if not row: return json_error('Unknown runId',404)
    return jsonify(build_response(json.loads(row['state_json'])))

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT','8000')))
