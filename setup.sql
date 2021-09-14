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
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('NA','fcp2','10.137.144.7','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcptz','NA','NA','NA','ROUSERTZ','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcptz','NA','NA','NA','FCCCTS','idmsView.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG,ia_dys) VALUES ('fcrstz','NA','NA','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N',3650);
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG,ia_dys) VALUES ('fbipp','NA','NA','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N',3650);

INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('NA','fcpug','10.153.30.14','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpug','NA','NA','NA','ROUSERUG','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
-- svc is NA pr ATM as it comes w/ SYS$USERS svc
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpug','NA','NA','NA','FCCCTS','idmsView.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpug','DTBANK1\UGPSVVCCOS1','10.137.128.93','SYSTEM','FCCCBOS','httpd.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.22','N');

INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('NA','fcp1','10.137.144.6','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpke','NA','NA','NA','ROUSERKE','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
--INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpke','','NA','NA','HPARCSITE','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpke','NA','NA','NA','FCCCTS','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpke','NA','NA','NA','FCCINTR','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcpke','NA','NA','NA','FCCPPAY','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'); --disabled
--INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('NA','KEPSVVCRFS1','10.137.130.11','dtbrefresh','ATM','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.31','N');

#all
DEF ct=tz; 
DEF e=t
DEF e=b
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG,ia_dys) VALUES ('fc&e&ct','NA','NA','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N',3650);
DEF val="'fc&e&ct','NA','NA','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";

DELETE FROM acl WHERE mc LIKE '%esb%';
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcp&ct','kepsvpcesb1.dtbank.net','10.137.129.66','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.23','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcp&ct','kepsvvcesb4.dtbank.net','10.137.129.58','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.24','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcp&ct','kepsvvcesb5.dtbank.net','10.137.129.59','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.25','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcp&ct','kepsvvcesb7.dtbank.net','10.137.129.61','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.26','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcp&ct','kedsvvcesb1.dtbank.net','10.137.129.41','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.27','N');
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcp&ct','kedsvvcesb1.dtbank.net','10.137.129.41','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.27','N');
UPDATE acl SET mc=REPLACE(mc,'.dtbank.net')  WHERE usr_db='ESB';
'SYS$USERS','KEDSVVCRFS1','10.137.130.135','DTBAdministrator','ATM','DBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.32','N'

# mac addr update
UPDATE acl SET mca='00:09:0f:09:00:1c' WHERE ip NOT LIKE '10.153.30%' and svc IN ('fcpug') AND NVL(mca,'NA')='NA';
UPDATE acl SET mca='00:09:0f:09:00:02' WHERE ip NOT LIKE '10.137.144%' and svc IN ('fcpke','fcptz') AND NVL(mca,'NA')='NA';
UPDATE acl SET mca='NA' WHERE ip ='NA';


--INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES ('fcp&ct','KEPSVVCGP1.dtbank.net','10.137.128.103','root','FCCGP','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.23','N');
-- ke|ug|tz
DEF ct=ke
DEF ctu=KE
DEF cu=K

DEF ct=tz
DEF ctu=TZ
DEF cu=T

DEF ct=ug
DEF ctu=UG
DEF cu=U
ALTER SESSION SET CURRENT_SCHEMA=acl;
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG) VALUES (&val);
commit;
'fcptz','DTBANK\KEPSVPCSQL1','10.137.145.42','sqldbadmin','FCCGP','sqlservr.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.11','N'
'fcptz','DTBANK\KEPSVPCSQL1','10.137.145.42','sqldbadmin','FCCGP','odbcad32.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.11','N'
'fcptz','DTBANK\KEPSVPCSQL2','10.137.145.43','sqldbadmin','FCCGP','sqlservr.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.12','N'
'fcptz','NA','10.137.145.43','gpadmin','FCCGP','sqlservr.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.12','N'
'fcptz','DTBANK\KEPSVPCSQL2','10.137.145.43','sqldbadmin','FCCGP','odbcad32.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.12','N'
#'fcpke','DTBANK\KEPSVVCGP1','10.137.128.103','gpadmin','FCCGP','sqlservr.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.14','N'            -- only ug
'fcptz','DTBANK\TZPSVVCCOS1','10.137.128.94','DTBAdministrator','FCCCBOS','odbcad32.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.13','N'
'fcptz','DTBANK\TZPSVVCCOS1','10.137.128.94','SYSTEM','FCCCBOS','httpd.exe',SYSDATE,SYSDATE+3650,'Y',6,22,'20.34.45.13','N'
'SYS$USERS','fcpug','127.0.0.1','db','SYS','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'127.0.0.1','N'  
DEF val="'SYS$USERS','NA','127.0.0.1','db','SYS','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'127.0.0.1','N'";     -- clone on diff svr => mc=NA
DEF val="'SYS$USERS','fcpug','127.0.0.1','mon','SYS','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'127.0.0.1','N'";  
DEF val="'fcp&ct','DTBANK\KEPSVVCJUMP1','10.137.144.44','mmburu','CCMS','NA',SYSDATE,SYSDATE+3,'Y',7,21,'20.34.45.83','N'";  
-- job
DEF val="'SYS$USERS','fcpug','127.0.0.1','db','DTBPUG','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'127.0.0.1','N'";  
DEF val="'SYS$USERS','GI-SERVER','NA','NA','DTBPUG','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";   #only ug
DEF val="'fcp&ct','kepsvvcgdpdb1','10.137.145.71','oracle','VISION','oracle@kepsvvcgdpdb5 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.21','N'";   
DEF val="'fcp&ct','kepsvvcgdpdb5','10.137.145.75','oracle','VISION','oracle@kepsvvcgdpdb5 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.22','N'";   
DEF val="'fcpug','kepsvvcgdpdb5','10.137.145.75','oracle','VISION','oracle@kepsvvcgdpdb5 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.22','N'";     --fcpug
DEF val="'fcp&ct','kedsvvcgdpdb1','10.137.145.146','grid','VISION','oracle@kedsvvcgdpdb1 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.145.75'),'N'";  
DEF val="'fcp&ct','kepsvvcgdpdb2','10.137.145.72','grid','ROUSER&ctu','oracle@kepsvvcgdpdb2 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.145.72'),'N'";   
DEF val="'fcp&ct','kepsvvcgdpdb3','10.137.145.73','grid','FCCPPAY','oracle@kepsvvcgdpdb3 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.145.73'),'N'";   
DEF val="'fcp&ct','kepsvvcgdpdb7','10.137.145.77','grid','FCCPPAY','oracle@kepsvvcgdpdb7 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.145.77'),'N'";  
DEF val="'fcpke','kepsvpcdbs3','10.137.128.75','DTBAdministrator','FCCPPAY','sqlplus.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.16','N'";   --ke 
DEF val="'fcp&ct','KEPSVVCVISAMA2','10.137.136.41','root','PCIBOX','"JDBC Thin Client"',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.17','N'";   
DEF val="'fcp&ct','KEPSVVCVISAMA3','10.137.136.42','root','PCIBOX','"JDBC Thin Client"',SYSDATE,SYSDATE+3650,'Y',0,23.59,'20.34.45.17','N'";  
DEF val="'fcp&ct','kepsvvcdbmgt1','10.148.81.131','DTBAdministrator','MCAFEEDVM','McAfeeDBS.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.81.131'),'N'";  
DEF val="'fcp&ct','kepsvvcdbmgt2','10.148.81.132','DTBAdministrator','MCAFEEDVM','McAfeeDBS.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.81.132'),'N'";  
DEF val="'fcp&ct','kedsvvcdbmgt1','10.147.81.132','DTBAdministrator','MCAFEEDVM','McAfeeDBS.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.147.81.132'),'N'";  
DEF val="'SYS$USERS','KEPSVPCDBS4','127.0.0.1','root','SYS','dbssensor@KEPSVPCDBS4 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,'127.0.0.1','N'";    #fcpke
DEF val="'SYS$USERS','KEPSVPCDBS4','127.0.0.1','mfedbs','SYS','dbssensor@KEPSVPCDBS4 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,'127.0.0.1','N'";    #fcpke mcafee
DEF val="'fcp&ct','jmp1','10.137.144.27','akilonzo','DTBP&ctu','sqlplus@jmp1 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.144.27'),'N'";  
DEF val="'fcp&ct','jmp1','10.137.144.27','tmbalo','DTBP&ctu','sqlplus@jmp1 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.144.27'),'N'";  
DEF val="'fcpug','NA','NA','NA','ROUSERUG','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";  
DEF val="'fcptz','NA','NA','NA','ROUSERTZ','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";  
DEF val="'fcp&ct','DTBANK\KEPSVVCSCREX1','10.137.128.104','DTBAdministrator','ROUSER&ctu','WScript.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.128.104'),'N'";  
DEF val="'fcp&ct','DTBANK\KEPSVVCSCREX1','10.137.128.104','DTBAdministrator','ROUSER&ctu','plsqldev.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.128.104'),'N'";  
DEF val="'fcp&ct','DTBANK\KEPSVVCGTT1','10.137.128.33','DTBAdministrator','ROUSER&ctu','sqlplus.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.128.33'),'N'";  
DEF val="'fcp&ct','kepsvvcgdpdb6','10.137.145.76','grid','ROUSER&ctu','oracle@kepsvvcgdpdb6 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.145.76'),'N'";  
DEF val="'fcpke','fcp2','10.137.144.7','gi','ROUSERKE','oracle@fcp2 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.144.7'),'N'";  
DEF val="'fcpke','kepsvpcesb1','10.137.129.66','root','ROUSERKE','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.129.66'),'N'";  
DEF val="'fcpke','KEPSVVIASCNT1','10.148.84.38','srssiemcollector','HPARCSITE','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.84.38'),'N'";  
DEF val="'fcpke','fcbke','10.137.144.32','db','CONNCHK','oracle@fcbke (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.144.32'),'N'";  
DEF val="'fcptz','fcbtz','10.137.144.33','db','CONNCHK','oracle@fcbtz (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.144.33'),'N'";  
DEF val="'fcpug','fcbtz','10.137.144.33','db','CONNCHK','oracle@fcbtz (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.144.33'),'N'";  
DEF val="'fcpug','fcbtz','10.153.30.14','db','CONNCHK','oracle@fcbtz (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.153.30.14'),'N'";  
DEF val="'fcpug','DTBANK\UGDSVVCCBOS1','10.137.128.187','SYSTEM','FCCCBOS','httpd.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.128.187'),'N'";  
DEF val="'fcpke','DTBANK\KEDSVVICPM1','10.148.84.4','PSMConnect','FCCCBOS','plsqldev.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.84.6'),'N'";  
DEF val="'fcpke','DTBANK\KEPSVVIPSWA1','10.148.84.5','PSMConnect','FCCCBOS','plsqldev.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.84.6'),'N'";  
DEF val="'fcpke','DTBANK\KEPSVVIPSM4','10.148.84.6','PSMConnect','FCCCBOS','plsqldev.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.84.6'),'N'";  
DEF val="'fcpke','DTBANK\KEPSVVIPSM3','10.148.84.7','PSMConnect','FCCCBOS','plsqldev.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.84.6'),'N'";  
DEF val="'fcpke','DTBANK\KEPSVVIPSMP2','10.148.84.11','PSMConnect','FCCCBOS','plsqldev.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.84.6'),'N'";  
DEF val="'fcpke','DTBANK\KEPSVVIPSMP3','10.148.84.12','PSMConnect','FCCCBOS','plsqldev.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.148.84.6'),'N'";  
DEF val="'fcptz','DTBTSVPRMX','10.127.3.32','root','IMPERVA','imperva.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.127.3.33'),'N'";  
DEF val="'fcptz','DTBTSVDRMX','10.127.3.34','root','IMPERVA','imperva.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.127.3.33'),'N'";  
DEF val="'fcptz','DTBTSVPRGW','10.127.3.37','root','IMPERVA','imperva.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.127.3.33'),'N'";  
DEF val="'fcptz','DTBTSVDRGW','10.127.3.38','root','IMPERVA','imperva.exe',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.127.3.33'),'N'";  
DEF val="'fcpug','DTBUSVPRMX','10.120.1.21','mxserver','IMPERVA','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.120.1.21'),'N'";  
DEF val="'fcpug','DTBUSVDRMX','10.120.2.21','mxserver','IMPERVA','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.120.2.21'),'N'";  
INSERT INTO acl (SVC, MC, IP, USR_OS, USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG)  SELECT SVC, MC, IP, 'PSMAdminConnect', USR_DB, PRG, DTL, DTT, ENABLED, TMB, TME, MIP,LOG  FROM acl WHERE usr_os='PSMConnect';
DEF val="'fcb','NA','NA','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";  
DEF val="'fcpke','DTBANK\KEPSVVIPCITIP1','10.148.80.178','!pwthiga','PCIBOX','DataDiscovery.exe',SYSDATE,SYSDATE+30,'Y',0,23.59,fnmip('10.148.80.178'),'N'";  
DEF val="'fcp&ct','kepsvpcesb.dtbank.net','10.137.129.81','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.129.81'),'N'";  
DEF val="'fcp&ct','kepsvpcesb4.dtbank.net','10.137.129.54','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.129.54'),'N'";  
DEF val="'fcp&ct','kedsvpcesb1.dtbank.net','10.137.129.154','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.129.154'),'N'";  
DEF val="'fcp&ct','kepsvvcesb3.dtbank.net','10.137.129.57','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.129.57'),'N'";  
DEF val="'fcp&ct','kepsvvcswlb1.dtbank.net','10.137.171.50','root','ESB','JDBC Thin Client',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.171.50'),'N'";  
DEF val="'fcp&ct','mon','10.137.144.43','mon','ACL','sqlplus@mon (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.144.43'),'N'";  
DEF val="'fcaug','NA','NA','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";  
DEF val="'fcpke','kepsvvcgdpdb3','10.137.145.73','oracle11','ROUSERKE','oracle@kepsvvcgdpdb3 (TNS V1-V3)',SYSDATE,SYSDATE+3650,'Y',0,23.59,fnmip('10.137.145.73'),'N'";  
--fcpke
DEF val="'SYS$USERS','DTBKRSFML01','NA','NA','DTBPKE','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";  
DEF val="'SYS$USERS','KEPSVVCFLEXML1','NA','NA','DTBPKE','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";  

--ssh
DEF val="'sshfcptz','NA','NA','NA','NA','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'NA','N'";  
UPDATE acl.acl SET ia_dys=3650 WHERE svc='sshfcptz';




'SYS$USERS','DTB&cu.RSFML01','NA','NA','DTBP&ctu','NA',SYSDATE,SYSDATE+3650,'Y',0,23.59,'10.137.144.40','N'  


UPDATE acl SET usr_db='ACL' WHERE usr_db='C##MON';
COMMIT;

SELECT DISTINCT ip,mip,mc FROM acl ORDER BY 2;
SELECT mip,ip,mc FROM acl WHERE mip In (SELECT mip FROM (SELECT DISTINCT ip,mip FROM acl WHERE ip!=mip) GROUP BY mip HAVING COUNT(*)>1) ORDER BY mip,ip;

route add -net 20.34.0.0 netmask 255.255.255.0  gw 192.168.1.100;




03-AUG-2019
----------
ALTER SESSION SET current_schema=acl;
ALTER TABLE acl ADD (mca VARCHAR2(17));
UPDATE acl SET mca='NA';
commit;
UPDATE acl SET enabled='N' WHERE usr_db LIKE 'ROUSER%' AND mip='NA';
UPDATE acl SET enabled='Y', mc='DTBANK\KEPSVVCJUMP1', ip='10.137.144.44', mip='20.34.45.83' WHERE usr_db LIKE 'ROUSER%' AND mip='NA';
UPDATE acl SET enabled='Y' WHERE usr_db LIKE 'FCCCTS%' AND mip='NA';
UPDATE acl SET enabled='Y' WHERE mc LIKE 'GI-SERVER' AND mip='NA';
commit;
SELECT DISTINCT mc,prg FROM acl_log WHERE usr_db LIKE 'ROUSER%';
SELECT DISTINCT  SVC, MC, USR_OS, USR_DB, PRG, MIP FROM acl_log WHERE mc LIKE '%kepsvvcgdpdb6%';
UPDATE acl SET mca='00:15:5d:50:a7:5b' WHERE mc LIKE '%JUMP%';
commit;
while read l; do ip=$(echo $l  | cut -d ' ' -f 1); mc=$(echo $l | cut -d ' ' -f 5);
< <(ip neighbour show | tr -s ' ' | cut -d ' ' -f 1,5|sort -u)

while read l; do ip=$(echo $l  | cut -d ' ' -f 1); sbn=$(echo $ip| cut -d'.' -f 1,2,3); mc=$(echo $l | cut -d ' ' -f 2);  echo $sbn $ip $mc; done < <(ip neighbour show | tr -s ' ' | cut -d ' ' -f 1,5| sort -u) 
 1>/tmp/acl <<< " SELECT DISTINCT SUBSTR(dbsvrip,1,INSTR(dbsvrip,'.',1,3)) sbn,ip FROM acl a JOIN fwParams f USING (svc) WHERE ip!='NA' ORDER BY 1;"




