import React, { useEffect, useState } from 'react';
import { motion, useSpring } from 'framer-motion';

const NumberTicker = ({ value, duration = 2, className = '' }) => {
    const [displayValue, setDisplayValue] = useState(0);
    const springValue = useSpring(0, { duration: duration * 1000 });

    useEffect(() => {
        springValue.set(value);

        const unsubscribe = springValue.on('change', (latest) => {
            setDisplayValue(Math.floor(latest));
        });

        return () => unsubscribe();
    }, [value, springValue]);

    return (
        <motion.span
            className={className}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
        >
            {displayValue.toLocaleString()}
        </motion.span>
    );
};

export default NumberTicker;
