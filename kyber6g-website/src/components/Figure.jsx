/* One of the paper's figures or plots (public/img, made by scripts/build_data.py) with its caption. */
export default function Figure({ name, caption, kind }) {
  return (
    <figure className="fig">
      <img src={`${import.meta.env.BASE_URL}img/${name}.png`} alt={caption} loading="lazy" />
      <figcaption>
        {kind && <span className={`kind kind-${kind.split(' ')[0]}`}>{kind}</span>}
        {caption}
      </figcaption>
    </figure>
  )
}
