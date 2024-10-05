const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  dbName: 'we'
})
.then(() => console.log('MongoDB connected to "we" database'))
.catch(err => console.log('MongoDB connection error:', err));

// Update User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  country: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  votes: [{
    matchId: String,
    vote: String
  }]
});

const User = mongoose.model('User', userSchema);


// Match Schema
const matchSchema = new mongoose.Schema({
  id: String,
  awayTeam: {
    id: Number,
    name: String,
    crest: String
  },
  competition: {
    id: Number,
    name: String,
    emblem: String
  },
  homeTeam: {
    id: Number,
    name: String,
    crest: String
  },
  lastUpdated: String,
  score: {
    winner: String,
    duration: String,
    fullTime: {
      home: Number,
      away: Number
    },
    halfTime: {
      home: Number,
      away: Number
    }
  },
  source: String,
  status: String,
  utcDate: String,
  votes: {
    HOME: { type: Number, default: 0 },
    DRAW: { type: Number, default: 0 },
    AWAY: { type: Number, default: 0 }
  },
  adminPrediction: {
    team: String,
    logo: String,
    isCorrect: Boolean  // New field to track if the prediction was correct
  }
});

const Match = mongoose.model('Match', matchSchema);

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (user && user.isAdmin) {
      next();
    } else {
      res.status(403).json({ message: 'Access denied. Admin only.' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Admin prediction endpoint
app.post('/api/admin/predict', verifyToken, isAdmin, async (req, res) => {
  try {
    const { matchId, prediction } = req.body;
          console.log('Received admin prediction:', { matchId, prediction });
    const match = await Match.findOne({ id: matchId });

    if (!match) {
      return res.status(404).json({ message: 'Match not found' });
    }

    match.adminPrediction = {
      team: prediction.team,
      logo: prediction.logo,
      isCorrect: null  // Will be updated when the match finishes
    };
    await match.save();

    res.json({ message: 'Admin prediction saved successfully' });
  } catch (error) {
    console.error('Error in admin prediction:', error);
    res.status(500).json({ message: 'Server error during prediction' });
  }
});

// Get all matches for admin (sorted by date)
app.get('/api/admin/matches', verifyToken, isAdmin, async (req, res) => {
  try {
    const { date } = req.query;
    console.log('Received request for admin matches on date:', date);

    const startDateString = `${date}T00:00:00+00:00`;
    const endDateString = `${date}T23:59:59+00:00`;

    const selectedLeagues = [253, 2, 3, 5, 9, 11, 12, 13, 39, 40, 45, 46, 61, 62, 71, 78, 79, 81, 88, 94, 103, 106, 113, 119, 128, 135, 140, 143, 144, 169, 172, 179, 197, 203, 207, 210, 218, 235, 271, 283, 286, 318, 327, 333, 345, 373, 383, 848];
    
    const matches = await Match.find({
      utcDate: {
        $gte: startDateString,
        $lt: endDateString
      },
      'competition.id': { $in: selectedLeagues }
    }).sort({ utcDate: 1 });
    
    console.log(`Found ${matches.length} matches for the date ${date}`);
    res.json(matches);
  } catch (error) {
    console.error('Error fetching admin matches:', error);
    res.status(500).json({ message: 'Server error fetching matches' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, country } = req.body;
    
    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      username,
      password: hashedPassword,
      country
    });

    // Save user to database
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// New endpoint to get country-based voting statistics
app.get('/api/country-stats', async (req, res) => {
  try {
    const users = await User.find({}, 'country votes');
    const countryStats = {};

    users.forEach(user => {
      if (!countryStats[user.country]) {
        countryStats[user.country] = { total: 0, correct: 0 };
      }
      user.votes.forEach(vote => {
        countryStats[user.country].total++;
        if (vote.correct) {
          countryStats[user.country].correct++;
        }
      });
    });

    const statsArray = Object.entries(countryStats).map(([country, stats]) => ({
      country,
      total: stats.total,
      correct: stats.correct,
      accuracy: stats.total > 0 ? (stats.correct / stats.total) * 100 : 0
    }));

    statsArray.sort((a, b) => b.accuracy - a.accuracy);

    res.json(statsArray);
  } catch (error) {
    console.error('Error fetching country stats:', error);
    res.status(500).json({ message: 'Server error fetching country stats' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Create and assign token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token, userId: user._id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Update vote endpoint to store user votes and return updated percentages
app.post('/api/vote', verifyToken, async (req, res) => {
  try {
    const { matchId, vote } = req.body;
    const match = await Match.findOne({ id: matchId });

    if (!match) {
      return res.status(404).json({ message: 'Match not found' });
    }

    if (!['SCHEDULED', 'TIMED'].includes(match.status)) {
      return res.status(400).json({ message: 'Voting is closed for this match' });
    }

    const user = await User.findById(req.user.id);
    const existingVote = user.votes.find(v => v.matchId === matchId);

    if (existingVote) {
      return res.status(400).json({ message: 'You have already voted for this match' });
    }

    match.votes[vote]++;
    await match.save();

    // Store user vote
    user.votes.push({ matchId, vote });
    await user.save();

    // Calculate percentages
    const totalVotes = match.votes.HOME + match.votes.DRAW + match.votes.AWAY;
    const percentages = {
      HOME: Math.round((match.votes.HOME / totalVotes) * 100) || 0,
      DRAW: Math.round((match.votes.DRAW / totalVotes) * 100) || 0,
      AWAY: Math.round((match.votes.AWAY / totalVotes) * 100) || 0
    };

    res.json({ message: 'Vote recorded successfully', percentages });
  } catch (error) {
    console.error('Error in /api/vote:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get match votes
app.get('/api/match-votes/:matchId', async (req, res) => {
  try {
    const match = await Match.findOne({ id: req.params.matchId });
    if (!match) {
      return res.status(404).json({ message: 'Match not found' });
    }

    const totalVotes = match.votes.HOME + match.votes.DRAW + match.votes.AWAY;
    const percentages = {
      HOME: Math.round((match.votes.HOME / totalVotes) * 100) || 0,
      DRAW: Math.round((match.votes.DRAW / totalVotes) * 100) || 0,
      AWAY: Math.round((match.votes.AWAY / totalVotes) * 100) || 0
    };

    res.json(percentages);
  } catch (error) {
    console.error('Error fetching match votes:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get user profile
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


app.get('/api/matches', async (req, res) => {
  try {
    const { date } = req.query;
    console.log('Fetching matches for date:', date);
    
    const startDateString = `${date}T00:00:00+00:00`;
    const endDateString = `${date}T23:59:59+00:00`;

    console.log('Querying for matches between', startDateString, 'and', endDateString);

    const matches = await Match.find({
      utcDate: {
        $gte: startDateString,
        $lt: endDateString
      },
      'competition.id': { $in: [253, 2, 3, 5, 848, 9, 11, 12, 13, 39, 40, 45, 46, 61, 62, 71, 78, 79, 81, 88, 94, 103, 106, 113, 119, 128, 135, 140, 143, 144, 169, 172, 179, 197, 203, 207, 210, 218, 235, 271, 283, 286, 318, 327, 333, 345, 373, 383,] }
    });
    
    console.log('Found matches:', matches.length);
    console.log('Matches by competition:', matches.reduce((acc, match) => {
      acc[match.competition.id] = (acc[match.competition.id] || 0) + 1;
      return acc;
    }, {}));      
      
    
    // Calculate fans' prediction for each match
    const matchesWithPrediction = matches.map(match => {
      const { HOME, DRAW, AWAY } = match.votes;
      let fansPrediction = null;
      
      if (HOME > DRAW && HOME > AWAY) {
        fansPrediction = {
          team: match.homeTeam.name,
          logo: match.homeTeam.crest
        };
      } else if (AWAY > DRAW && AWAY > HOME) {
        fansPrediction = {
          team: match.awayTeam.name,
          logo: match.awayTeam.crest
        };
      } else if (DRAW > HOME && DRAW > AWAY) {
        fansPrediction = {
          team: 'Draw',
          logo: null
        };
      }
              console.log('Match admin prediction:', match.adminPrediction);


    return {
      ...match.toObject(),
      fansPrediction,
      adminPrediction: match.adminPrediction
    };
  });

    console.log('Found matches:', matchesWithPrediction.length);
    res.json(matchesWithPrediction);
  } catch (error) {
    console.error('Error in /api/matches:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/vote', async (req, res) => {
  try {
    const { matchId, vote } = req.body;
    const match = await Match.findOne({ id: matchId });

    if (!match) {
      return res.status(404).json({ message: 'Match not found' });
    }

    if (!['SCHEDULED', 'TIMED'].includes(match.status)) {
      return res.status(400).json({ message: 'Voting is closed for this match' });
    }

    match.votes[vote]++;
    
    // Calculate fan vote
    const { HOME, DRAW, AWAY } = match.votes;
    if (HOME > DRAW && HOME > AWAY) {
      match.fanVote = match.homeTeam.name;
    } else if (AWAY > DRAW && AWAY > HOME) {
      match.fanVote = match.awayTeam.name;
    } else if (DRAW > HOME && DRAW > AWAY) {
      match.fanVote = 'Draw';
    } else {
      match.fanVote = 'No majority';
    }

    await match.save();
    res.json({ message: 'Vote recorded successfully', fanVote: match.fanVote });
  } catch (error) {
    console.error('Error in /api/vote:', error);
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/match/:matchId', verifyToken, async (req, res) => {
  try {
    const match = await Match.findOne({ id: req.params.matchId });
    if (!match) {
      return res.status(404).json({ message: 'Match not found' });
    }
    res.json({
      id: match.id,
      homeTeam: match.homeTeam,
      awayTeam: match.awayTeam,
      competition: match.competition,
      utcDate: match.utcDate,
      status: match.status,
      score: match.score,  // Include the entire score object
      votes: match.votes,  // Include voting information
      adminPrediction: match.adminPrediction  // Include admin prediction if available
    });
  } catch (error) {
    console.error('Error fetching match details:', error);
    res.status(500).json({ message: 'Server error fetching match details' });
  }
});

// New endpoint for prediction statistics
app.get('/api/prediction-stats', async (req, res) => {
  try {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    console.log('Date ranges:');
    console.log('Yesterday:', yesterday.toISOString());
    console.log('Today:', today.toISOString());
    console.log('Tomorrow:', tomorrow.toISOString());

    const calculateCumulativeStats = async (startDate, endDate) => {
      const finishedMatches = await Match.find({
        status: 'FINISHED',
        utcDate: { $gte: startDate.toISOString(), $lt: endDate.toISOString() }
      });

      console.log(`Found ${finishedMatches.length} finished matches between ${startDate.toISOString()} and ${endDate.toISOString()}`);

      let userCorrectPredictions = 0;
      let adminCorrectPredictions = 0;
      let totalUserPredictions = 0;
      let totalAdminPredictions = 0;

      for (const match of finishedMatches) {
        const homeScore = match.score.fullTime.home;
        const awayScore = match.score.fullTime.away;
        const actualResult = homeScore > awayScore ? 'HOME' : homeScore < awayScore ? 'AWAY' : 'DRAW';
        
        // Determine fans' majority vote
        const { HOME, DRAW, AWAY } = match.votes;
        const fansPrediction = HOME > DRAW && HOME > AWAY ? 'HOME' : 
                               AWAY > DRAW && AWAY > HOME ? 'AWAY' : 'DRAW';

        if (fansPrediction === actualResult) {
          userCorrectPredictions++;
        }
        totalUserPredictions++;

        if (match.adminPrediction && match.adminPrediction.team) {
          let adminPredictionResult;
          if (match.adminPrediction.team === match.homeTeam.name) {
            adminPredictionResult = 'HOME';
          } else if (match.adminPrediction.team === match.awayTeam.name) {
            adminPredictionResult = 'AWAY';
          } else if (match.adminPrediction.team === 'Draw') {
            adminPredictionResult = 'DRAW';
          }
          
          if (adminPredictionResult === actualResult) {
            adminCorrectPredictions++;
          }
          totalAdminPredictions++;
        }
      }

      const userAccuracy = totalUserPredictions > 0 ? (userCorrectPredictions / totalUserPredictions) * 100 : 0;
      const adminAccuracy = totalAdminPredictions > 0 ? (adminCorrectPredictions / totalAdminPredictions) * 100 : 0;

      return { 
        userAccuracy, 
        adminAccuracy, 
        totalUserPredictions, 
        totalAdminPredictions, 
        userCorrectPredictions, 
        adminCorrectPredictions 
      };
    };

    const todayStats = await calculateCumulativeStats(new Date(0), tomorrow);
    const yesterdayStats = await calculateCumulativeStats(new Date(0), today);

    const userTrend = todayStats.userAccuracy - yesterdayStats.userAccuracy;
    const adminTrend = todayStats.adminAccuracy - yesterdayStats.adminAccuracy;

    const result = {
      today: todayStats,
      yesterday: yesterdayStats,
      userTrend,
      adminTrend
    };

    console.log('Final result:', JSON.stringify(result, null, 2));

    res.json(result);
  } catch (error) {
    console.error('Error calculating prediction stats:', error);
    res.status(500).json({ message: 'Server error calculating prediction stats' });
  }
});

app.post('/api/admin/reset-predictions', verifyToken, isAdmin, async (req, res) => {
  try {
    // Reset user votes
    await User.updateMany({}, { $set: { votes: [] } });

    // Reset admin predictions and user votes on matches
    await Match.updateMany({}, {
      $set: {
        adminPrediction: null,
        votes: { HOME: 0, DRAW: 0, AWAY: 0 }
      }
    });

    res.json({ message: 'All predictions and votes have been reset successfully.' });
  } catch (error) {
    console.error('Error resetting predictions:', error);
    res.status(500).json({ message: 'Server error while resetting predictions' });
  }
});


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));