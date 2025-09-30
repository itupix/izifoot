export type PlayerId = string;
export type Position = 'GARDIEN' | 'DEFENSEUR' | 'MILIEU' | 'ATTAQUANT';

export interface Player {
  id: PlayerId;
  name: string;
  primary: Position;
  secondary?: Position;
  trainingsCount?: number;
  plateausCount?: number;
}

export interface Training {
  id: string;
  date: string;
  present: PlayerId[];
}

export interface Plateau {
  id: string;
  date: string;
  lieu: string;
  matches: Match[];
}

export type MatchType = 'ENTRAINEMENT' | 'PLATEAU';

export interface Match {
  id: string;
  type: MatchType;
  home: PlayerId[];
  away: PlayerId[];
  starters?: PlayerId[];
  subs?: PlayerId[];
  score?: { home: number; away: number };
  buteurs?: { playerId: PlayerId; side: 'home' | 'away' }[];
}