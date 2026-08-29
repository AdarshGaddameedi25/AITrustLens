'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

export const GlobalCursor = () => {
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setMousePosition({
        x: e.clientX,
        y: e.clientY,
      });
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  return (
    <motion.div
      className="pointer-events-none fixed inset-0 z-50 overflow-hidden"
      animate={{ opacity: 1 }}
      initial={{ opacity: 0 }}
    >
      <div
        className="absolute w-[600px] h-[600px] rounded-full blur-[100px] bg-sky-200/20 mix-blend-screen transition-transform duration-300 ease-out"
        style={{
          transform: `translate(${mousePosition.x - 300}px, ${mousePosition.y - 300}px)`,
        }}
      />
    </motion.div>
  );
};
