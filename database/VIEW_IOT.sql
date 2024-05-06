drop view if exists ALL_RESULTS_IOT;

CREATE VIEW ALL_RESULTS_IOT AS
SELECT * FROM vulnerability_detection_IOT;

drop view if exists NOT_FINISH_RESULTS;

CREATE VIEW NOT_FINISH_RESULTS_IOT AS
SELECT * FROM vulnerability_detection_IOT
WHERE vulnerability_detection_IOT.finish_detect=FALSE;

drop view if exists FINISH_RESULTS_IOT;

CREATE VIEW FINISH_RESULTS_IOT AS
SELECT * FROM vulnerability_detection_IOT
WHERE vulnerability_detection_IOT.finish_detect=TRUE;

drop view if exists FINISH_RESULTS_NUMBER_IOT;

CREATE VIEW FINISH_RESULTS_NUMBER_IOT AS
SELECT count(*) FROM vulnerability_detection_IOT
WHERE vulnerability_detection_IOT.finish_detect=TRUE;
