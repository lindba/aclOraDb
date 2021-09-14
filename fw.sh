. ./sv.cfg; fws=$tmp/fwt1.sh; cp -p fw.tmplt $fws;
for sd in $(echo $dbs | sed -e "s/,/ /g"); do
 svr=$(echo $sd | cut -d ':' -f 1); db=$(echo $sd | cut -d '@' -f 2); #t dbSvc=$(echo $db | cut -d '/' -f 2); 
 ssh1 $svr <<!
  rm -f $fws; cd scripts; sqlplus -s $monUsr/$monPswd@$db 1>/dev/null <<!!
   SET TRIMSPOOL ON;
   --DEF cl1="||REPLACE(TO_CHAR(MIN(tmb),90.99),'.',':')||' '||REPLACE(TO_CHAR(MAX(tme),90.99),'.',':')||' '||MAX(DECODE(mip,'NA','',mip)) ||' '||MAX(DECODE(mca,'NA','',mca))  FROM acl a JOIN fwParams f USING (svc)";
   DEF cl1="||REPLACE(TO_CHAR(MIN(tmb),90.99),'.',':')||' '||REPLACE(TO_CHAR(MAX(tme),90.99),'.',':')||' '||MAX(mip) ||' '||MAX(mca)  FROM acl a JOIN fwParams f USING (svc)";
  --DECODE(a.svc,'NA',f.svc,a.svc)=f.svc";
   DEF cl2=" WHERE ip IS NOT NULL AND enabled!='N' AND dtt>SYSDATE AND dtl > SYSDATE-ia_dys GROUP BY svc,ip ORDER BY 1 DESC";
   DEF cl3=")||' '||MAX(";
   @/home/mon/scripts/login
   spool $fws append ;
    SELECT DISTINCT 'ipNat '||DECODE(ip,'NA','0.0.0.0/0',ip)||' '||MAX(fwPrt&cl3.dbSvrIp&cl3.dbPrt&cl3.wd)||' '&cl1&cl2;
   spool off;
   spool /tmp/kl.sql
    SELECT 'ALTER SYSTEM KILL SESSION '''||sid||','||serial#||',@'||inst_id||''' IMMEDIATE;' FROM GV\\\$SESSION WHERE event LIKE '%PL/SQL lock timer%';
   spool off;
   @/tmp/kl.sql
!!
<<tmp
   spool /tmp/acl$dbSvc
    COLUMN sbn FORMAT A30;
    SELECT DISTINCT SUBSTR(dbsvrip,1,INSTR(dbsvrip,'.',1,3)-1)||'-'||ip sbn  FROM acl a JOIN fwParams f USING (svc) WHERE ip!='NA' ORDER BY 1;
   spool off;
tmp
!
ssh1 $svr "cat $fws" >> $fws;  #t ssh -q $svr "grep -v '^$' /tmp/acl$dbSvc.lst" > /tmp/acl$dbSvc.lst;
done

echo "iptables -t nat -A POSTROUTING  -j MASQUERADE" >> $fws;

chmod +x $fws;
for fw in $(echo $svrFw | sed -e "s/,/ /g"); do scp -p $fws root@$fw:/tmp; ssh -q root@$fw /tmp/fwt1.sh;  #t rm -f /tmp/ns$fw;
 #t while read l; do ip=$(echo $l  | cut -d ' ' -f 1); sbn=$(echo $ip| cut -d'.' -f 1,2,3); mc=$(echo $l | cut -d ' ' -f 2);  echo $sbn-$ip $mc >> /tmp/ns$fw; done < <(ssh -q root@$fw ip neighbour show | tr -s ' ' | cut -d ' ' -f 1,5| sort -u)
 #t for f in $(ls /tmp/acl*.lst); do join -j 1 $f /tmp/ns$fw; done;
done;



/*
 INSERT INTO fwParams VALUES('fcrstz','10.127.3.1',1571,2672);
 -- ssh
 INSERT INTO fwParams VALUES('sshfcptz','10.137.144.20',2340,2220);
*/
