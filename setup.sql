-- enhancement:
 fw (svc, mc, ip, usr_os_nm,usr_os_id, prg, dtl, dtt, tmb, tme,wd,mca).   
 human user: login w/ predefd pswd (pd)  -> change pswd to random(pr) + discon user -> email pr to owner -> login w/ pr -> change pswd to pd.               appln svr: ia_dys=1, proxy user fe appln svr (change pswd often)
 job: db(usr_db,mip,src_prt(V$SESSION.port,ip_local_port_range),update dtl) fcubs(dtbpke.smtb_current_users). 
 audit: fw dropped req, db

--initial setup
DEF monUsr=$monUsr
DEF monPswd=$monPswd
 CREATE USER &monUsr IDENTIFIED BY "&monPswd";
 ALTER USER acl IDENTIFIED BY "hjy^84";
 GRANT CREATE TABLE TO &monUsr;
 GRANT CREATE SESSION TO &monUsr;
 GRANT DBA TO &monUsr;
 GRANT CREATE TABLE,CREATE SESSION TO &monUsr;
 ALTER USER &monUsr QUOTA UNLIMITED ON system;
 GRANT SELECT on V_$SESSION TO &monUsr;
 GRANT SELECT on V_$INSTANCE TO &monUsr;
 GRANT SELECT on V_$DATABASE TO &monUsr;
 GRANT EXECUTE ON DBMS_LOCK TO  &monUsr;
 GRANT EXECUTE ON DBMS_MVIEW TO  &monUsr;
!
-- master svr (mon):
 a script to interactive (sqlplus) login to individual db and batch login to individual or >1 dbs.

-- every db
 ALTER SESSION SET CURRENT_SCHEMA=&monUsr;
 DROP TABLE &monUsr..acl;
 CREATE TABLE &monUsr..acl(svc VARCHAR2(10) NOT NULL, mc VARCHAR2(100) NOT NULL, ip VARCHAR2(15), usr_os  VARCHAR2(20) NOT NULL, usr_db VARCHAR2(30) NOT NULL, prg VARCHAR2(41) NOT NULL, dtl DATE DEFAULT SYSDATE NOT NULL, 
  dtt DATE DEFAULT '31-DEC-2020' NOT NULL, enabled CHAR(1) DEFAULT 'C' NOT NULL, tmb NUMBER DEFAULT 7 NOT NULL, tme NUMBER DEFAULT 20 NOT NULL, 
  wd VARCHAR2(27) DEFAULT 'Mon,Tue,Wed,Thu,Fri,Sat,Sun', mip VARCHAR2(15), log CHAR(1) DEFAULT 'N', ia_dys NUMBER DEFAULT 35, mca VARCHAR2(17) PRIMARY KEY (svc,mc,usr_os,usr_db,prg,tmb,tme));
 mip: add rt on svr, allow in sqlnet,ora
 DROP TABLE &monUsr..acl_log;
 CREATE TABLE &monUsr..acl_log AS SELECT SYSDATE dt, svc,mc,usr_os,usr_db,prg,mip,log FROM acl WHERE 2>6;
 DROP TABLE &monUsr..fwparams;
 CREATE TABLE &monUsr..fwparams(svc VARCHAR2(10), dbSvrIp VARCHAR2(30), dbPrt NUMBER, fwPrt NUMBER);
/*
 CREATE OR REPLACE FUNCTION fnacl RETURN VARCHAR2 AS r VARCHAR2(20); BEGIN
  SELECT aclid INTO r FROM (SELECT ROWNUM aclid FROM ALL_OBJECTS WHERE ROWNUM<=10000 MINUS SELECT aclid FROM aclm ORDER BY 1 ) WHERE ROWNUM<=1; RETURN r;
 END;
/
*/
 CREATE OR REPLACE FUNCTION fnmip (pip acl.ip%TYPE) RETURN VARCHAR2 AS mip acl.mip%TYPE; ip3Incr NUMBER; ip4Incr NUMBER; ip1p NUMBER; ip2p NUMBER; ip3p NUMBER; ip12 VARCHAR2(8); ip3 NUMBER; ip4 NUMBER; 
BEGIN 
 ip3Incr:=10; ip4Incr:=8; ip12:='20.34'; 
 ip1p:=INSTR(pip,'.',1); ip2p:=INSTR(pip,'.',ip1p+1); ip3p:=INSTR(pip,'.',ip2p+1); 
 ip3:=MOD(SUBSTR(pip,ip2p+1,ip3p-ip2p-1)+ip3Incr,255); ip4:=MOD(SUBSTR(pip,ip3p+1,LENGTH(pip))+ip4Incr,255); 
 RETURN ip12||'.'||ip3||'.'||ip4;
END;
/
SHOW ERRORS;
UPDATE acl SET mip=fnmip(ip) WHERE mc NOT LIKE'%psvvcfap%' AND ip NOT LIKE '10.137.144.%' AND ip NOT LIKE '10.153.30%' AND mip NOT IN ('NA','127.0.0.1');
  
  SELECT aclid INTO r FROM (SELECT ROWNUM aclid FROM ALL_OBJECTS WHERE ROWNUM<=10000 MINUS SELECT aclid FROM aclm ORDER BY 1 ) WHERE ROWNUM<=1; RETURN r;

INSERT INTO acl VALUES('p1hs','db1','192.168.0.102','db','U1HS','sqlplus@db1 (TNS V1-V3)',SYSDATE,'28-SEP-2018::12-05-39','Y','0','23','Mon,Tue,Wed,Thu,Fri,Sat,Sun','15.2.20.2','N','35',1);

 #12c dbs
  DEF om=" WHERE oracle_maintained='Y'";
  EXEC FOR p in (SELECT * FROM DBA_SYS_PRIVS WHERE privilege='ADMINISTER DATABASE TRIGGER' AND grantee NOT IN (SELECT role FROM DBA_ROLES &om UNION SELECT username FROM DBA_USERS &om)) LOOP EXECUTE IMMEDIATE 'REVOKE '||p.privilege||' FROM '||p.grantee; END LOOP;
  COLUMN grantee FORMAT A20; 
  COLUMN granted_role FORMAT A20; 
/*
 DROP DATABASE LINK mon;
 CREATE DATABASE LINK mon CONNECT TO &monUsr IDENTIFIED BY "&monPswd" USING 'mon';
 DROP TABLE dtl;
 CREATE TABLE dtl ( aclid NUMBER PRIMARY KEY, dtl DATE DEFAULT SYSDATE NOT NULL);
 DROP MATERIALIZED VIEW acl;
 CREATE MATERIALIZED VIEW acl AS SELECT svc, mc, usr_os, usr_db, prg, dtl, dtt, mip, log,aclid FROM aclm@mon NATURAL JOIN dtl WHERE svc ='&db' AND enabled!='N' AND dtt>SYSDATE AND dtl > SYSDATE-ia_dys;
*/
<<doc
 BEQ: 19.1:  SYS_CONTEXT('USERENV','IP_ADDRESS') => 127.0.0.1
doc

 ALTER SESSION SET CURRENT_SCHEMA=acl;
 ALTER SYSTEM SET "_system_trig_enabled"=false;
 spool /tmp/t1hs.sql
  SELECT 'ALTER SYSTEM KILL SESSION '''||sid||','||serial#||',@'||inst_id||''' IMMEDIATE;' FROM GV$SESSION WHERE event LIKE '%PL/SQL lock timer%';
 spool off;
 @/tmp/t1hs.sql
 TRUNCATE TABLE acl_log;
 SELECT * FROM acl_log;
 --DEF mvwRf="DBMS_MVIEW.refresh('ACL');";
 DEF sysCtx="SYS_CONTEXT('USERENV',"
 DEF clsSvc="svc IN(lsvcCtx,'NA')";
 DEF c1=" WHERE &clsSvc AND mip IN (lip,'NA') AND mc IN (lmc,'NA') AND usr_os  IN (losusr,'NA') AND SYSDATE BETWEEN dtl AND dtt AND SYSDATE-dtl<=ia_dys AND enabled!='N'";
 DEF c2=" AND usr_db IN (lusr,'NA')";
 DEF c3=" AND prg IN (lprg,'NA')";
 --DEF clsDblink="'ALTER SESSION CLOSE DATABASE LINK mon'";
 CREATE OR REPLACE PROCEDURE pses_validate AS lusr acl.usr_db%TYPE; lsvcCtx acl.svc%TYPE; lip acl.mip%TYPE; lmc acl.mc%TYPE; losusr acl.usr_os%TYPE; 
  lprg acl.prg%TYPE; ldtl DATE; h NUMBER:=TO_CHAR(SYSDATE,'HH24.MI'); llog acl.log%TYPE; lop VARCHAR2(20);
 BEGIN
  SELECT open_mode INTO lop FROM V$DATABASE;
  FOR s IN (SELECT sid,serial#,machine,osuser,username,module,program FROM V$SESSION WHERE sid=&sysCtx'SID') ) --AND NVL(program,'nAlwd') NOT LIKE 'oracle@% (%)')
  LOOP lusr:=s.username; lsvcCtx:=&sysCtx'SERVICE_NAME'); lip:=NVL(&sysCtx'IP_ADDRESS'),'127.0.0.1'); /*BEQ 11g*/ lmc:=s.machine; losusr:=s.osuser; lprg:=s.program;
   SELECT MIN(dtl) INTO ldtl FROM acl &c1&c2&c3; SELECT MAX(log) INTO llog FROM acl &c1&c2&c3; 
   IF ldtl IS NULL THEN IF llog='F' AND lop!='READ ONLY' THEN INSERT INTO acl_log VALUES(SYSDATE,lsvcCtx,lmc,losusr,lusr,lprg,lip,llog); COMMIT; END IF;
    DBMS_APPLICATION_INFO.set_action('NA_'||lip); DBMS_LOCK.sleep (3600); RAISE_APPLICATION_ERROR(-20010, ' not allowed'); END IF;
   IF TRUNC(ldtl)!=TRUNC(SYSDATE) AND lop!='READ ONLY' THEN UPDATE acl SET dtl=SYSDATE &c1&c2&c3; COMMIT; END IF;
   IF llog='S' AND lop!='READ ONLY' THEN INSERT INTO acl_log VALUES(SYSDATE,lsvcCtx,lmc,losusr,lusr,lprg,lip,llog); COMMIT; END IF;
  END LOOP;  END;
/
 SHOW ERRORS;
 CREATE OR REPLACE TRIGGER ses_validate AFTER LOGON ON DATABASE BEGIN pses_validate; END;
/
 ALTER SYSTEM SET "_system_trig_enabled"=true;


INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG)   SELECT svc,MACHINE,ip,OS_USER,SES_USER,PROG,LDATE,TDATE,ENABLED,BTIME,ETIME,mip,log FROM c##mon.aclhs;
