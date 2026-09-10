import { useRef, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Float } from '@react-three/drei'
import * as THREE from 'three'

function Drone({ position, speed, index }) {
    const ref = useRef()
    const offset = useMemo(() => index * 1.3, [index])

    useFrame(({ clock }) => {
        const t = clock.getElapsedTime() * speed * 0.3
        ref.current.position.x = position[0] + Math.sin(t + offset) * 2.5
        ref.current.position.z = position[2] + Math.cos(t * 0.7 + offset) * 2
        ref.current.position.y = position[1] + Math.sin(t * 1.2 + offset) * 0.4
        ref.current.rotation.y = t + offset
    })

    return (
        <group ref={ref} position={position}>
            {/* Body */}
            <mesh>
                <boxGeometry args={[0.3, 0.1, 0.3]} />
                <meshStandardMaterial color="#7c3aed" metalness={0.6} roughness={0.3} />
            </mesh>
            {/* Arms */}
            {[[-0.25, 0, -0.25], [0.25, 0, -0.25], [-0.25, 0, 0.25], [0.25, 0, 0.25]].map((pos, i) => (
                <group key={i} position={pos}>
                    <mesh>
                        <cylinderGeometry args={[0.02, 0.02, 0.2, 6]} />
                        <meshStandardMaterial color="#4b5563" />
                    </mesh>
                    <mesh position={[0, 0.12, 0]}>
                        <torusGeometry args={[0.08, 0.01, 4, 16]} />
                        <meshStandardMaterial color="#9ca3af" transparent opacity={0.6} />
                    </mesh>
                </group>
            ))}
            {/* Status light */}
            <pointLight color="#7c3aed" intensity={0.5} distance={2} />
        </group>
    )
}

function GnbTower({ position }) {
    return (
        <group position={position}>
            {/* Tower */}
            <mesh position={[0, 1.5, 0]}>
                <cylinderGeometry args={[0.08, 0.12, 3, 8]} />
                <meshStandardMaterial color="#374151" metalness={0.8} roughness={0.2} />
            </mesh>
            {/* Antenna panels */}
            {[0, Math.PI * 0.67, Math.PI * 1.33].map((rot, i) => (
                <mesh key={i} position={[Math.sin(rot) * 0.2, 2.8, Math.cos(rot) * 0.2]} rotation={[0, rot, 0]}>
                    <boxGeometry args={[0.3, 0.5, 0.04]} />
                    <meshStandardMaterial color="#0891b2" metalness={0.5} roughness={0.3} />
                </mesh>
            ))}
            {/* Base */}
            <mesh position={[0, 0.05, 0]}>
                <cylinderGeometry args={[0.4, 0.4, 0.1, 8]} />
                <meshStandardMaterial color="#6b7280" />
            </mesh>
            {/* Signal indicator */}
            <pointLight color="#0891b2" intensity={0.8} distance={5} position={[0, 3, 0]} />
        </group>
    )
}

function CommunicationLink({ from, to, color = '#7c3aed' }) {
    const ref = useRef()

    useFrame(({ clock }) => {
        if (!ref.current) return
        const mat = ref.current.material
        mat.dashOffset = -clock.getElapsedTime() * 2
    })

    const points = useMemo(() => {
        const curve = new THREE.QuadraticBezierCurve3(
            new THREE.Vector3(...from),
            new THREE.Vector3((from[0] + to[0]) / 2, Math.max(from[1], to[1]) + 1.5, (from[2] + to[2]) / 2),
            new THREE.Vector3(...to)
        )
        return curve.getPoints(32)
    }, [from, to])

    const geometry = useMemo(() => {
        return new THREE.BufferGeometry().setFromPoints(points)
    }, [points])

    return (
        <line ref={ref} geometry={geometry}>
            <lineDashedMaterial color={color} dashSize={0.2} gapSize={0.1} transparent opacity={0.4} />
        </line>
    )
}

function Ground() {
    return (
        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.1, 0]} receiveShadow>
            <planeGeometry args={[30, 30, 30, 30]} />
            <meshStandardMaterial color="#1e293b" wireframe transparent opacity={0.15} />
        </mesh>
    )
}

function GridFloor() {
    return (
        <gridHelper args={[30, 30, '#334155', '#1e293b']} position={[0, -0.05, 0]} />
    )
}

function Scene() {
    const dronePositions = useMemo(() => [
        [0, 3, 0], [2, 3.5, -1], [-2, 3.2, 1], [1.5, 3.8, 2],
        [-1, 3.3, -2], [3, 3.6, 0.5], [-3, 3.4, -0.5], [0.5, 3.1, 3],
        [-2.5, 3.7, 2], [1, 3.5, -3], [2.5, 3.2, -2], [-1.5, 3.4, 1.5]
    ], [])

    const gnbPositions = useMemo(() => [
        [-5, 0, -4], [5, 0, -4], [0, 0, 5], [-6, 0, 3], [6, 0, 3]
    ], [])

    const droneSpeeds = useMemo(() => (
        dronePositions.map((_, i) => 0.8 + (i % 5) * 0.08)
    ), [dronePositions])

    return (
        <>
            <ambientLight intensity={0.3} />
            <directionalLight position={[10, 15, 5]} intensity={0.6} color="#e2e8f0" />
            <pointLight position={[0, 8, 0]} intensity={0.4} color="#818cf8" />

            <GridFloor />
            <Ground />

            {dronePositions.map((pos, i) => (
                <Drone key={i} position={pos} speed={droneSpeeds[i]} index={i} />
            ))}

            {gnbPositions.map((pos, i) => (
                <GnbTower key={i} position={pos} />
            ))}

            {/* Communication links from drones to nearest gNBs */}
            {dronePositions.slice(0, 6).map((dp, i) => {
                const nearestGnb = gnbPositions.reduce((best, gp) => {
                    const dist = Math.hypot(dp[0] - gp[0], dp[2] - gp[2])
                    const bestDist = Math.hypot(dp[0] - best[0], dp[2] - best[2])
                    return dist < bestDist ? gp : best
                })
                return (
                    <CommunicationLink
                        key={i}
                        from={dp}
                        to={[nearestGnb[0], 2.8, nearestGnb[2]]}
                        color={i % 2 === 0 ? '#7c3aed' : '#0891b2'}
                    />
                )
            })}

            <Float speed={0.5} rotationIntensity={0} floatIntensity={0.3}>
                <mesh position={[0, 6, 0]}>
                    <sphereGeometry args={[0.15, 16, 16]} />
                    <meshStandardMaterial color="#7c3aed" emissive="#7c3aed" emissiveIntensity={0.5} />
                </mesh>
            </Float>

            <OrbitControls
                enableZoom={false}
                enablePan={false}
                autoRotate
                autoRotateSpeed={0.5}
                maxPolarAngle={Math.PI / 2.2}
                minPolarAngle={Math.PI / 4}
            />

            <fog attach="fog" args={['#0f172a', 10, 28]} />
        </>
    )
}

export default function DroneSwarmScene() {
    return (
        <div className="scene-container" aria-label="Interactive 3D drone swarm visualization">
            <Canvas
                camera={{ position: [8, 6, 8], fov: 50 }}
                gl={{ antialias: true, alpha: false }}
                style={{ background: '#0f172a' }}
            >
                <Scene />
            </Canvas>
            <div style={{
                position: 'relative',
                bottom: '40px',
                textAlign: 'center',
                color: '#64748b',
                fontSize: '0.7rem',
                fontFamily: 'var(--font-sans)',
                letterSpacing: '0.04em',
                pointerEvents: 'none',
            }}>
                INTERACTIVE — DRAG TO ROTATE
            </div>
        </div>
    )
}
