class Comment(db.Model):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    blogpost_id = Column(Integer, ForeignKey('blog_posts.id'))
    author_id = Column(Integer, ForeignKey('user.id'))
    author = relationship("User", back_populates="child")
    post = relationship("BlogPost", back_populates="comments")
    text = Column(Str, nullable=False)