import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { io } from 'socket.io-client';
import Dashboard from './components/Dashboard';
import Events from './components/Events';
import Blacklist from './components/Blacklist';
import Login from './components/Login';
import Navbar from './components/Navbar';
import './App.css';

// Create dark theme for cybersecurity dashboard
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00ff88',
    },
    secondary: {
      main: '#ff4444',
    },
    background: {
      default: '#0a0a0a',
      paper: '#1a1a1a',
    },
  },
});

function App() {
  const [socket, setSocket] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Check if user is already authenticated
    const token = localStorage.getItem('authToken');
    if (token) {
      setIsAuthenticated(true);
      setUser({ username: localStorage.getItem('username') });
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      // Initialize SocketIO connection
      const newSocket = io('http://localhost:8000', {
        transports: ['websocket', 'polling'],
      });

      newSocket.on('connect', () => {
        console.log('Connected to SentinelShield server');
      });

      newSocket.on('disconnect', () => {
        console.log('Disconnected from SentinelShield server');
      });

      newSocket.on('security_event', (event) => {
        console.log('Security event received:', event);
        // You can add global event handling here
      });

      setSocket(newSocket);

      return () => {
        newSocket.close();
      };
    }
  }, [isAuthenticated]);

  const handleLogin = (userData) => {
    setIsAuthenticated(true);
    setUser(userData);
    localStorage.setItem('authToken', 'dummy-token');
    localStorage.setItem('username', userData.username);
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUser(null);
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    if (socket) {
      socket.close();
    }
  };

  if (!isAuthenticated) {
    return (
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <Login onLogin={handleLogin} />
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <div className="App">
          <Navbar user={user} onLogout={handleLogout} />
          <Routes>
            <Route path="/dashboard" element={<Dashboard socket={socket} />} />
            <Route path="/events" element={<Events socket={socket} />} />
            <Route path="/blacklist" element={<Blacklist socket={socket} />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </div>
      </Router>
    </ThemeProvider>
  );
}

export default App; 