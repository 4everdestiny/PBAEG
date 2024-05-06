drop view if exists ALL_RESULTS;

CREATE VIEW ALL_RESULTS AS
SELECT * FROM vulnerability_detection;

drop view if exists NOT_FINISH_RESULTS;

CREATE VIEW NOT_FINISH_RESULTS AS
SELECT * FROM vulnerability_detection
WHERE vulnerability_detection.finish_detect=FALSE;

drop view if exists FINISH_RESULTS;

CREATE VIEW FINISH_RESULTS AS
SELECT * FROM vulnerability_detection
WHERE vulnerability_detection.finish_detect=TRUE;

drop view if exists FINISH_RESULTS_NUMBER;

CREATE VIEW FINISH_RESULTS_NUMBER AS
SELECT count(*) FROM vulnerability_detection
WHERE vulnerability_detection.finish_detect=TRUE;
