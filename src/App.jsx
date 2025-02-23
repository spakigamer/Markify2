import { useState } from 'react'
import Props from './Mark'
import MyComponent from './display'
import Home from './Home'
import Nav from './Navbar/nav'
import { BrowserRouter as Router, Route, Routes, BrowserRouter } from "react-router-dom";
import Footer from './Navbar/footer'
import Contact from './Contact'
import Login from './Login'
import SignUp from './SignUp'
import Dashboard from './Dashboard'
import Card from './Card'
import Create from './Create'
import ProtectedRoute from './ProtectedRoute'
import MarkdownEditor from './Editor'
import './App.css'

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
    <Router>
    <Routes>
    <Route path='/' element={<Home/>}></Route>
    <Route path="/login" element={<Login />} />
    <Route path="/signup" element={<SignUp />} />
    <Route path='/contact' element={<Contact></Contact>}></Route>
    <Route path='/dashboard' element={<ProtectedRoute><Dashboard></Dashboard></ProtectedRoute>}></Route>
    <Route path='/mark' element={<Props></Props>}></Route>
    <Route path='/editor' element={<ProtectedRoute><MarkdownEditor></MarkdownEditor></ProtectedRoute>}></Route>
    </Routes>
    </Router>
    </>
  )
}

export default App
