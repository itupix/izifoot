-- Performance indexes for high-traffic list/detail queries
CREATE INDEX IF NOT EXISTS "Player_teamId_idx" ON "Player"("teamId");
CREATE INDEX IF NOT EXISTS "Player_teamId_last_name_first_name_name_idx" ON "Player"("teamId", "last_name", "first_name", "name");

CREATE INDEX IF NOT EXISTS "Training_teamId_date_idx" ON "Training"("teamId", "date");
CREATE INDEX IF NOT EXISTS "Plateau_teamId_date_idx" ON "Plateau"("teamId", "date");

CREATE INDEX IF NOT EXISTS "Attendance_session_type_session_id_teamId_idx" ON "Attendance"("session_type", "session_id", "teamId");

CREATE INDEX IF NOT EXISTS "Match_plateauId_createdAt_idx" ON "Match"("plateauId", "createdAt");
CREATE INDEX IF NOT EXISTS "Scorer_matchId_idx" ON "Scorer"("matchId");
CREATE INDEX IF NOT EXISTS "MatchTeamPlayer_playerId_idx" ON "MatchTeamPlayer"("playerId");
