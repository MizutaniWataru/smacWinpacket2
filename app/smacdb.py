# -*- coding: utf-8 -*-

import MySQLdb as db
import json
from datetime import datetime, timedelta


def get_connection():
    return db.connect(
        host="mariadb",
        user="user",
        passwd="password",
        port=3306,
        db="smac",
        charset="utf8",
    )


def json_serial(obj):
    if isinstance(obj, (datetime)):
        return obj.strftime("%Y-%m-%d %H:%M:%S")


def execute_get_srecort_rep_id(cursor, seis_id):
    sql = "select rep_point from seismic_record where seis_id = %s"
    cursor.execute(sql, [seis_id])
    data = json.dumps(cursor.fetchall(), default=json_serial)
    return json.loads(data)[0]["rep_point"]


def execute_get_seismic_record_id(cursor, seis_id):
    sql = "select * from seismic_record where seis_id = %s"
    cursor.execute(sql, [seis_id])
    data = json.dumps(cursor.fetchall(), default=json_serial)
    return json.loads(data)[0]


def get_seismic_record_id(seis_id):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    data = execute_get_seismic_record_id(cursor, seis_id)
    conn.close()
    return data


def execute_get_seismic_detail_id(cursor, seis_id):
    sql = "select * from seismic_detail where seis_id = %s order by point"
    cursor.execute(sql, [seis_id])
    data = json.dumps(cursor.fetchall(), default=json_serial)
    return json.loads(data)


def get_seismic_detail_id(seis_id):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    data = execute_get_seismic_detail_id(cursor, seis_id)
    conn.close()
    return data


def execute_get_booting_seismic_id(cursor):
    sql = "select seis_id from seismic_record where stop_date is NULL and category = 1 order by seis_id desc limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    d = json.loads(data)
    if len(d) == 0:
        return -1
    else:
        return d[0]["seis_id"]


def get_booting_seismic_id():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sid = execute_get_booting_seismic_id(cursor)
    conn.close()
    return sid


def get_last_cal_date():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select stop_date from seismic_record where category = 2 and stop_date is not null order by stop_date desc limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    d = json.loads(data)
    if len(d) == 0:
        return datetime.now()
    else:
        return datetime.strptime(d[0]["stop_date"], "%Y-%m-%d %H:%M:%S")


def execute_get_seis_id(cursor):
    sql = "select seis_id from seismic_record order by seis_id desc limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    d = json.loads(data)
    if len(d) == 0:
        return 1
    else:
        return d[0]["seis_id"] + 1


def get_seis_id():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sid = execute_get_seis_id(cursor)
    conn.close()
    return sid


def get_seisid(conn):
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select seis_id from seismic_record order by seis_id desc limit 1"
    cursor.execute(sql)
    data = json.loads(json.dumps(cursor.fetchall(), default=json_serial))
    if len(data) == 0:
        return 1
    return int(data[0]["seis_id"]) + 1


def get_seismic_record_top():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from seismic_record where category = 1 order by start_date desc limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def get_smac_status():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from smac_status limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)[0]


def get_dev_status():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    cursor.execute("select dev_status from smac_status limit 1")
    row = cursor.fetchone()
    conn.close()
    if not row or row.get("dev_status") is None:
        return None
    return int(row["dev_status"])


def get_sensor_status():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from sensor_status"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def update_sensor_status(sensors):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        sql = "update sensor_status set sensor1 = %s, sensor2 = %s, sensor3 = %s, sensor4 = %s, sensor5 = %s, sensor6 = %s, update_date = NOW()"
        cursor.execute(
            sql,
            (sensors[0], sensors[1], sensors[2], sensors[3], sensors[4], sensors[5]),
        )
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute_update_smac_status(cursor, status):
    sql = "update gps_status set con_status = %s, last_sync_time = %s, re_holdover = %s, pll_lock = %s, latitude = %s, longitude = %s, height = %s, update_date = NOW()"
    cursor.execute(
        sql,
        (
            status["con_status"],
            status["last_sync_time"],
            status["re_holdover"],
            status["pll_lock"],
            status["latitude"],
            status["longitude"],
            status["height"],
        ),
    )
    sql = "update power_status set sw_voltage = %s, bat_voltage = %s, digital_voltage = %s, update_date = NOW()"
    cursor.execute(
        sql, (status["sw_voltage"], status["bat_voltage"], status["digital_voltage"])
    )
    # sql = "update sensor_status set sensor1 = %s, sensor2 = %s, sensor3 = %s, sensor4 = %s, sensor5 = %s, sensor6 = %s, update_date = NOW()"
    # cursor.execute(sql, (status["sensor1"], status["sensor2"], status["sensor3"], status["sensor4"], status["sensor5"], status["sensor6"]))


def execute_update_srecord(cursor, eq):
    rp = execute_get_srecort_rep_id(cursor, eq["sid"])
    detail = execute_get_seismic_detail_id(cursor, eq["sid"])
    i = 0
    for d in detail:
        ed = eq["pdata"][i]
        if ed["shindo"] < 0:
            ed["shindo"] = 0

        if d["seis_intensity"] < ed["shindo"]:
            sql = "update seismic_detail set seis_intensity = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["shindo"], eq["sid"], ed["point"]))
            if d["point"] == rp:
                sql = "update seismic_record set seis_intensity = %s, update_date = NOW() where seis_id = %s"
                cursor.execute(sql, (ed["shindo"], eq["sid"]))
        if d["si"] < ed["si"]:
            sql = "update seismic_detail set si = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["si"], eq["sid"], ed["point"]))
        if d["max_ns"] < ed["max_ns"]:
            sql = "update seismic_detail set max_ns = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["max_ns"], eq["sid"], ed["point"]))
        if d["max_ew"] < ed["max_ew"]:
            sql = "update seismic_detail set max_ew = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["max_ew"], eq["sid"], ed["point"]))
        if d["max_ud"] < ed["max_ud"]:
            sql = "update seismic_detail set max_ud = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["max_ud"], eq["sid"], ed["point"]))
        if d["max_horizontal"] < ed["max_hz"]:
            sql = "update seismic_detail set max_horizontal = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["max_hz"], eq["sid"], ed["point"]))
        if d["max_three"] < ed["max_3"]:
            sql = "update seismic_detail set max_three = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["max_3"], eq["sid"], ed["point"]))
        if d["res1"] < ed["res1"]:
            sql = "update seismic_detail set res1 = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["res1"], eq["sid"], ed["point"]))
        if d["res2"] < ed["res2"]:
            sql = "update seismic_detail set res2 = %s, update_date = NOW() where seis_id = %s and point = %s"
            cursor.execute(sql, (ed["res2"], eq["sid"], ed["point"]))

        sql = "update seismic_detail set last_seis_intensity = %s, last_si = %s, last_ns = %s, last_ew = %s, last_ud = %s, last_horizontal = %s, last_three = %s, last_res1 = %s, last_res2 = %s where seis_id = %s and point = %s"
        cursor.execute(
            sql,
            (
                ed["shindo"],
                ed["si"],
                ed["max_ns"],
                ed["max_ew"],
                ed["max_ud"],
                ed["max_hz"],
                ed["max_3"],
                ed["res1"],
                ed["res2"],
                eq["sid"],
                ed["point"],
            ),
        )

        i += 1


def execute_stop_srecord(cursor, eq):
    sid = execute_get_booting_seismic_id(cursor)
    sql = "update seismic_record set stop_date = %s, update_date = NOW() where seis_id = %s"
    cursor.execute(sql, (eq["stop_date"], sid))


def execute_create_srecord(cursor, eq, rp):
    sid = execute_get_seis_id(cursor)
    # rp = execute_get_basic_setting(cursor)["rep_point"]
    shindo = eq["pdata"][rp - 1]["shindo"] if eq["pdata"][rp - 1]["shindo"] > 0 else 0
    sql = "insert into seismic_record(seis_id, category, start_date, rep_point, seis_intensity, filepath, create_date, update_date) values(%s, 1, %s, %s, %s, %s, NOW(), NOW())"
    cursor.execute(sql, (sid, eq["start_date"], rp, shindo, eq["filepath"]))

    sql = "insert into seismic_detail (seis_id, point, seis_intensity, si, max_ns, max_ew, max_ud, max_horizontal, max_three, res1, res2, create_date, update_date) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())"
    for pd in eq["pdata"]:
        cursor.execute(
            sql,
            (
                sid,
                pd["point"],
                pd["shindo"],
                pd["si"],
                pd["max_ns"],
                pd["max_ew"],
                pd["max_ud"],
                pd["max_hz"],
                pd["max_3"],
                pd["res1"],
                pd["res2"],
            ),
        )


def update_smac_and_eq(status, eq, sflg, eflg, etype, rp):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        if sflg:
            execute_update_smac_status(cursor, status)
        if eflg:
            if etype & 1 == 1:
                srecord = execute_get_seismic_record_id(cursor, eq["sid"])
                if srecord["start_date"] != eq["start_date"]:
                    etype |= 2
                    eq["stop_date"] = datetime.now()
                else:
                    execute_update_srecord(cursor, eq)
            if etype & 2 == 2:
                execute_stop_srecord(cursor, eq)
            if etype & 4 == 4:
                execute_create_srecord(cursor, eq, rp)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_latest_cal_record():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from seismic_record where category = 2 and stop_date is not null order by stop_date desc limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def get_cal_detail_by_id(sid):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from cal_detail where seis_id = %s"
    cursor.execute(sql, [sid])
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def create_cal_record():
    sid = -1
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        sid = execute_get_seis_id(cursor)
        rp = execute_get_basic_setting(cursor)["rep_point"]
        sql = "insert into seismic_record(seis_id, category, rep_point, seis_intensity, create_date, update_date) values(%s, 2, %s, -1, NOW(), NOW())"
        cursor.execute(sql, (sid, rp))
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()
    return sid


def stop_cal_record(sid, boot, stop):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        sql = "update seismic_record set start_date = %s, stop_date = %s, update_date = NOW() where seis_id = %s"
        cursor.execute(sql, (boot, stop, sid))
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_cal_detail(sid, ch, freq, current, target, value, snr, offset):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    error = round(((value - target) / target) * 100.0, 1)
    try:
        sql = "insert into cal_detail(seis_id, ch_code, cal_exe_freq, cal_exe_current, exe_target, measured_value, cal_snr, measured_error, measured_offset, create_date, update_date) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())"
        cursor.execute(sql, (sid, ch, freq, current, target, value, snr, error, offset))
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_device_status(status):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        sql = "update device_status set dev_status = %s, update_date = NOW()"
        cursor.execute(sql, [status])
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute_update_ssd_status(cursor, pon, tmp, rem):
    sql = "update ssd_status set poweron_time = %s, temperature = %s, rem_capacity = %s, update_date = NOW()"
    cursor.execute(sql, (pon, tmp, rem))


def update_ssd_status(pon, tmp, rem):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_ssd_status(cursor, pon, tmp, rem)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_ssd_status():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from ssd_status limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)[0]


def execute_update_last_sync_time(cursor, stime):
    sql = "update gps_status set last_sync_time = %s, update_date = NOW()"
    cursor.execute(sql, [stime])


def update_ssd_and_last_sync(pon, tmp, rem, stime):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_ssd_status(cursor, pon, tmp, rem)
        execute_update_last_sync_time(cursor, stime)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_seismic_record_detail(category, bootdate, rep, fpath, slist):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        seis_id = get_seisid(conn)
        sql = "insert into seismic_record (seis_id, category, start_date, rep_point, seis_intensity, filepath, create_date, update_date) values(%s, %s, %s, %s, %s, %s, NOW(), NOW())"
        cursor.execute(
            sql, (seis_id, category, bootdate, rep, slist[rep - 1]["shindo"], fpath)
        )

        sql = "insert into seismic_detail (seis_id, point, seis_intensity, si, max_ns, max_ew, max_ud, max_horizontal, max_three, create_date, update_date) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())"
        for i in range(len(slist)):
            cursor.execute(
                sql,
                (
                    seis_id,
                    i + 1,
                    slist[i]["shindo"],
                    slist[i]["si"],
                    slist[i]["max_ns"],
                    slist[i]["max_ew"],
                    slist[i]["max_ud"],
                    slist[i]["max_horizontal"],
                    slist[i]["max_three"],
                ),
            )

        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_seismic_detail_id(seis_id):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from seismic_detail where seis_id = %s order by point"
    cursor.execute(sql, [seis_id])
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def get_seismic_record_top():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from seismic_record where category = 1 order by start_date desc limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def update_contact_status(cno, enable):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        sql = "update contact_status set contact%s = %s, update_date = NOW()"
        cursor.execute(sql, (cno, enable))
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute_get_basic_setting(cursor):
    sql = "select * from basic_setting limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    return json.loads(data)[0]


def get_basic_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    data = execute_get_basic_setting(cursor)
    conn.close()
    return data


def execute_update_basic_setting(cursor, scode, sname, hold, speriod, rep_point):
    sql = "update basic_setting set station_code = %s, station_name = %s, screen_hold = %s, search_period = %s, rep_point = %s, update_date = NOW()"
    cursor.execute(sql, (scode, sname, hold, speriod, rep_point))


def update_basic_setting(scode, sname, hold, speriod, rep_point):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_basic_setting(cursor, scode, sname, hold, speriod, rep_point)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_point_channel_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from point_channel_setting"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def execute_update_point_channel_setting(cursor, dlist):
    for d in dlist:
        if (
            d["ch_code_ns"] == d["ch_code_ew"]
            or d["ch_code_ns"] == d["ch_code_ud"]
            or d["ch_code_ew"] == d["ch_code_ud"]
        ):
            return False

        sql = "update point_setting set point_name = %s, ch_code_ns = %s, ch_code_ew = %s, ch_code_ud = %s, update_date = NOW() where point = %s"
        cursor.execute(
            sql,
            (
                d["point_name"],
                d["ch_code_ns"],
                d["ch_code_ew"],
                d["ch_code_ud"],
                d["point"],
            ),
        )
        sql = "update channel_setting set ch_enable = %s, gain = %s, full_scale = %s, cal_freq = %s, cal_current = %s, cal_adjustment = %s, update_date = NOW() where ch_code = %s"
        cursor.execute(
            sql,
            (
                d["ns_enable"],
                d["ns_gain"],
                d["ns_full_scale"],
                d["ns_cal_freq"],
                d["ns_cal_current"],
                d["ns_cal_adj"],
                d["ch_code_ns"],
            ),
        )
        cursor.execute(
            sql,
            (
                d["ew_enable"],
                d["ew_gain"],
                d["ew_full_scale"],
                d["ew_cal_freq"],
                d["ew_cal_current"],
                d["ew_cal_adj"],
                d["ch_code_ew"],
            ),
        )
        cursor.execute(
            sql,
            (
                d["ud_enable"],
                d["ud_gain"],
                d["ud_full_scale"],
                d["ud_cal_freq"],
                d["ud_cal_current"],
                d["ud_cal_adj"],
                d["ch_code_ud"],
            ),
        )


def update_point_channel_setting(dlist):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_point_channel_setting(cursor, dlist)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_trigger_rec_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from trigger_rec_setting"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)[0]


def execute_update_trigger_rec_setting(cursor, hpf, decimation, freq, f0, t0, k):
    sql = "update trigger_rec_setting set trec_sample_freq = %s, f0 = %s, t0 = %s, K = %s, trec_hpf = %s, trec_decimation = %s, update_date = NOW()"
    cursor.execute(sql, (freq, f0, t0, k, hpf, decimation))


def update_trigger_rec_setting(hpf, decimation, freq, f0, t0, k):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_trigger_rec_setting(cursor, hpf, decimation, freq, f0, t0, k)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_trigger_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    data = []
    try:
        sql = "select stop_time, min_rec_time, max_rec_time, expression from trigger_rec_setting limit 1"
        cursor.execute(sql)
        data = json.loads(json.dumps(cursor.fetchall(), default=json_serial))[0]
        sql = "select * from trigger_setting"
        cursor.execute(sql)
        tset = json.loads(json.dumps(cursor.fetchall(), default=json_serial))
        data["trigger"] = tset
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()
    return data


def execute_update_trigger_setting(
    cursor, stop_time, min_rec_time, max_rec_time, expr, tset
):
    sql = "update trigger_rec_setting set stop_time = %s, min_rec_time = %s, max_rec_time = %s, expression = %s, update_date = NOW()"
    cursor.execute(sql, (stop_time, min_rec_time, max_rec_time, expr))
    sql = "delete from trigger_setting"
    cursor.execute(sql)
    tid = 1
    for t in tset:
        sql = "insert into trigger_setting(trig_id, trig_factor, factor_type, start_level, stop_level, avg_trigger, start_filter, update_date) values(%s,%s,%s,%s,%s,%s,%s, NOW())"
        cursor.execute(
            sql,
            (
                tid,
                t["trig_factor"],
                t["factor_type"],
                t["start_level"],
                t["stop_level"],
                t["avg_trigger"],
                t["start_filter"],
            ),
        )
        tid += 1


def update_trigger_setting(stop_time, min_rec_time, max_rec_time, expr, tset):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_trigger_setting(
            cursor, stop_time, min_rec_time, max_rec_time, expr, tset
        )
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_contact_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from contact_setting"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)


def execute_update_contact_setting(cursor, clist):
    for c in clist:
        sql = "update contact_setting set sig_setting = %s, factor = %s, threshold = %s, active_time = %s, update_date = NOW() where contact_id = %s"
        cursor.execute(
            sql,
            (
                c["sig_setting"],
                c["factor"],
                c["threshold"],
                c["active_time"],
                c["contact_id"],
            ),
        )


def update_contact_setting(clist):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_contact_setting(cursor, clist)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_constant_rec_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from constant_rec_setting limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)[0]


def execute_update_constant_rec_setting(
    cursor, enable, start_date, stop_date, cycle, day, freq, hpf, decimation
):
    sql = "update constant_rec_setting set cr_enable = %s, start_date = %s, stop_date = %s, exe_cycle = %s, exe_day = %s, crec_sample_freq = %s, crec_hpf = %s, crec_decimation = %s, update_date = NOW()"
    cursor.execute(
        sql, (enable, start_date, stop_date, cycle, day, freq, hpf, decimation)
    )


def update_constant_rec_setting(
    enable, start_date, stop_date, cycle, day, freq, hpf, decimation
):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_constant_rec_setting(
            cursor, enable, start_date, stop_date, cycle, day, freq, hpf, decimation
        )
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_cloud_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "select * from cloud_setting limit 1"
    cursor.execute(sql)
    data = json.dumps(cursor.fetchall(), default=json_serial)
    conn.close()
    return json.loads(data)[0]


def execute_update_cloud_setting(cursor, bnews, cnews, jinterval):
    sql = "update cloud_setting set breaking_news = %s, confirmed_news = %s, no_judgement_interval = %s, update_date = NOW()"
    cursor.execute(sql, (bnews, cnews, jinterval))


def update_cloud_setting(bnews, cnews, jinterval):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_cloud_setting(cursor, bnews, cnews, jinterval)
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_all_setting():
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    data = []
    try:
        sql = "select * from union_setting limit 1"
        cursor.execute(sql)
        data = json.loads(json.dumps(cursor.fetchall(), default=json_serial))[0]
        sql = "select * from basic_setting"
        cursor.execute(sql)
        basic = json.loads(json.dumps(cursor.fetchall(), default=json_serial))
        data["basic"] = basic
        sql = "select * from point_channel_setting"
        cursor.execute(sql)
        pcs = json.loads(json.dumps(cursor.fetchall(), default=json_serial))
        data["point_channel"] = pcs
        sql = "select * from trigger_setting"
        cursor.execute(sql)
        ts = json.loads(json.dumps(cursor.fetchall(), default=json_serial))
        data["trigger"] = ts
        sql = "select * from contact_setting"
        cursor.execute(sql)
        cs = json.loads(json.dumps(cursor.fetchall(), default=json_serial))
        data["contact"] = cs
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()
    return data


def update_all_setting(settings):
    conn = get_connection()
    cursor = conn.cursor(db.cursors.DictCursor)
    sql = "start transaction"
    cursor.execute(sql)
    try:
        execute_update_basic_setting(
            cursor,
            settings["station_code"],
            settings["station_name"],
            settings["screen_hold"],
            settings["search_period"],
            settings["rep_point"],
        )
        execute_update_point_channel_setting(cursor, settings["point_channel"])
        execute_update_trigger_rec_setting(
            cursor,
            settings["trec_hpf"],
            settings["trec_decimation"],
            settings["trec_sample_freq"],
            settings["f0"],
            settings["t0"],
            settings["K"],
        )
        execute_update_trigger_setting(
            cursor,
            settings["stop_time"],
            settings["min_rec_time"],
            settings["max_rec_time"],
            settings["expression"],
            settings["trigger"],
        )
        execute_update_contact_setting(cursor, settings["contact"])
        execute_update_constant_rec_setting(
            cursor,
            settings["cr_enable"],
            settings["start_date"],
            settings["stop_date"],
            settings["exe_cycle"],
            settings["exe_day"],
            settings["crec_sample_freq"],
            settings["crec_hpf"],
            settings["crec_decimation"],
        )
        execute_update_cloud_setting(
            cursor,
            settings["breaking_news"],
            settings["confirmed_news"],
            settings["no_judgement_interval"],
        )
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()
