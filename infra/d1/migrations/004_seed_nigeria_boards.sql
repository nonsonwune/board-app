-- Seed Nigerian federal universities (generated)
BEGIN TRANSACTION;
INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('abu', 'Ahmadu Bello university', 'Zaria', strftime('%s','now')*1000, 1500, 11.1528, 7.6544)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('abuja', 'University of Abuja,', 'P.M.B. 117, Gwagwalada F.C.T Abuja., FCT', strftime('%s','now')*1000, 1500, 8.9443, 7.0814)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('bayero', 'Bayero University', 'P.M.B 3011, Kano, Kano', strftime('%s','now')*1000, 1500, 12.0463, 8.5246)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('bauchi', 'Abubakar Tatawa Balewa University', 'P.M.B. 0248, Bauchi., Bauchi', strftime('%s','now')*1000, 1500, 10.2829, 9.843)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('benin', 'Universitv of Benin', 'P.M.B 1154. Benin City', strftime('%s','now')*1000, 1500, 6.404, 5.6037)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('calabar', 'Universitv of Calabar', 'P.M.B 1115,Calabar', strftime('%s','now')*1000, 1500, 4.9508, 8.322)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-dutse', 'Federal University, Dutse', 'Jigawa State, Jigawa', strftime('%s','now')*1000, 1500, 12.5152, 9.2937)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-dutsinma', 'Federal University. DUTSINMA,', 'KATSINA STATE, Katsina', strftime('%s','now')*1000, 1500, 12.452, 7.493)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-gashua', 'Federa Universitv. Gashua', 'Yobe State, Yobe', strftime('%s','now')*1000, 1500, 12.873, 11.0452)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-gusau', 'Federal University, Gusau', 'Zamfara State, Zamfara', strftime('%s','now')*1000, 1500, 12.1707, 6.6718)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-kashere', 'rederal University, kashere', 'Gombe state, Gombe', strftime('%s','now')*1000, 1500, 9.8019, 11.1888)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-kebbi', 'Federal University, Birnin-Kebbi', 'Birnin-Kebbi, Kebbi State, Kebbi', strftime('%s','now')*1000, 1500, 12.5884, 4.1995)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-lafia', 'Federal University, Latia', 'P.M.B. 146, Lafia, Nasarawa State., Nasarawa', strftime('%s','now')*1000, 1500, 8.4889, 8.5356)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-lokoja', 'Federal University, Lokoja', 'Kogi State, Kogi', strftime('%s','now')*1000, 1500, 7.7956, 6.7375)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('aefuna', 'Alex Ekwueme Federal University, Ndufu-Alike', 'Ebonyi State,, Ebonyi', strftime('%s','now')*1000, 1500, 6.4357, 7.5173)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-otuoke', 'Federal University, Otuoke', 'Bayelsa state, Bayelsa', strftime('%s','now')*1000, 1500, 4.787, 6.0681)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('fed-wukari', 'Federal University, Wukari', '200 Katsina-Ala Road, P.M.B 1020, Wukari Taraba State, Katsina', strftime('%s','now')*1000, 1500, 7.8617, 9.7778)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('ibadan', 'University Of Ibadan', 'Ibadan, Oyo state, Oyo', strftime('%s','now')*1000, 1500, 7.4415, 3.8873)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('ilorin', 'University of Ilorin', 'P.M.B .1515, Ilorin', strftime('%s','now')*1000, 1500, 8.4799, 4.6746)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('jos', 'University of Jos', 'P.M.B. 2084, Jos Plateau State, Plateau', strftime('%s','now')*1000, 1500, 9.8965, 8.859)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('lagos', 'University of Lagos', 'Akoka, Lagos State, Lagos', strftime('%s','now')*1000, 1500, 6.5159, 3.389)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('maiduguri', 'University of Maiduguri', 'P.M.B 1069, Maiduguri,', strftime('%s','now')*1000, 1500, 11.846, 13.1542)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('makurdi', 'Joseph Sarwuan Tarka University', 'Makurdi, Benue State., Benue', strftime('%s','now')*1000, 1500, 7.7033, 8.5378)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('naub', 'wigerian Army university', 'Biu, Borno state, Borno', strftime('%s','now')*1000, 1500, 10.6126, 12.1943)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('nda', 'Nigerian Detence Academy', 'P.M.B. 2109, Kaduna, Kaduna State, Kaduna', strftime('%s','now')*1000, 1500, 10.5506, 7.4383)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;

INSERT INTO boards (id, display_name, description, created_at, radius_meters, latitude, longitude)
VALUES ('oau', 'Obafemi Awolowo University''', 'lle-Ife, Osun State, Osun', strftime('%s','now')*1000, 1500, 7.5163, 4.5223)
ON CONFLICT(id) DO UPDATE SET
  display_name=excluded.display_name,
  description=excluded.description,
  radius_meters=excluded.radius_meters,
  latitude=excluded.latitude,
  longitude=excluded.longitude;
COMMIT;
